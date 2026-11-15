use anyhow::Result;
use clap::{FromArgMatches, parser::ValueSource};
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

// Override the global allocator with mimalloc on musl-target builds. musl's
// default malloc is dramatically slower than glibc's ptmalloc under the
// kind of multi-threaded allocation pressure log normalization produces —
// observed 4-19× slowdown on this codebase, matching the 2-20× range the
// rust-cli ecosystem reports (ripgrep, fd, et al. ship the same fix).
// On glibc we keep the system allocator; ptmalloc is already fast enough
// and avoiding mimalloc's slightly higher resident-memory cost there is
// preferable for dev builds.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use lessence::cli::{self, Cli, RunShape};
use lessence::config::{self, Config, GroupSink, OutputFormat};
use lessence::folder::{PatternFolder, SourceId, SummaryRequest};
use lessence::ingest::{self, Event, Ingestor};
use lessence::output::{self, write_or_exit_on_closed_pipe};

enum DiffExit {
    Same,
    Moved,
    ComparisonFailed,
}

impl DiffExit {
    fn code(self) -> i32 {
        match self {
            Self::Same => 0,
            Self::Moved => 1,
            Self::ComparisonFailed => 2,
        }
    }
}

enum SummaryMode {
    Off,
    Text,
    JsonTopN { capped_by_default: bool },
}

const FIT_ROWS_FOR_COMMAND_FOOTER_PROMPT_AND_BUFFER: usize = 4;
const FIT_MIN_ROWS_WORTH_FITTING: usize = 3;

fn exit_usage_error(e: impl std::fmt::Display) -> ! {
    eprintln!("lessence: {e}");
    std::process::exit(2);
}

fn reject_report_flags_outside_fold(cli: &Cli) {
    if (cli.help_human || cli.skill.is_some() || cli.completions.is_some() || cli.diff.is_some())
        && let Err(e) = cli.report_plan(RunShape::OtherRun)
    {
        exit_usage_error(e);
    }
}

fn early_dispatch(cli: &Cli) -> Option<Result<()>> {
    if cli.help_human {
        return Some(
            io::stdout()
                .write_all(cli::HELP_HUMAN.as_bytes())
                .map_err(Into::into),
        );
    }
    if let Some(topic) = &cli.skill {
        let Some(text) = lessence::skill::render(topic, cli::VERSION) else {
            exit_usage_error(format_args!(
                "unknown --skill topic '{topic}' (expected one of: {})",
                lessence::skill::TOPICS.join(", ")
            ));
        };
        return Some(io::stdout().write_all(text.as_bytes()).map_err(Into::into));
    }
    if let Some(shell) = cli.completions {
        let mut cmd = cli::command();
        clap_complete::generate(shell, &mut cmd, "lessence", &mut io::stdout());
        return Some(Ok(()));
    }
    if let Some(other) = &cli.diff {
        let checked = if cli.distilling() {
            cli.validate_distill()
        } else {
            cli.validate_diff()
        };
        if let Err(e) = checked {
            exit_usage_error(e);
        }
        let exit = match std::env::current_exe()
            .map_err(anyhow::Error::from)
            .and_then(|me| lessence::diff::print_moved_groups(other, &me, &cli.files, "1"))
        {
            Ok(0) => DiffExit::Same,
            Ok(_) => DiffExit::Moved,
            Err(e) => {
                eprintln!("lessence: --diff: {e:#}");
                DiffExit::ComparisonFailed
            }
        };
        std::process::exit(exit.code());
    }
    None
}

fn nothing_to_fold(cli: &Cli) -> bool {
    cli.files.is_empty() && io::stdin().is_terminal()
}

fn resolve_explain_format(cli: &Cli, format: OutputFormat, format_given: bool) -> OutputFormat {
    if !cli.explain || format == OutputFormat::Json {
        return format;
    }
    if format_given {
        exit_usage_error(format_args!(
            "--explain annotates JSON group records; --format {} cannot carry \
             them. Drop --format or use --format json",
            cli.format
        ));
    }
    OutputFormat::Json
}

fn resolve_summary_mode(cli: &Cli, format: OutputFormat) -> SummaryMode {
    let requested = cli.summary || (cli.fit && cli.top.is_none());
    match (requested, format) {
        (false, _) => SummaryMode::Off,
        (true, OutputFormat::Json) => SummaryMode::JsonTopN {
            capped_by_default: cli.top.is_none(),
        },
        (true, _) => SummaryMode::Text,
    }
}

fn fit_budget(cli: &Cli) -> Option<usize> {
    if cli.fit && std::io::stdout().is_terminal() {
        terminal_size::terminal_size()
            .map(|(_, h)| {
                (h.0 as usize).saturating_sub(FIT_ROWS_FOR_COMMAND_FOOTER_PROMPT_AND_BUFFER)
            })
            .filter(|&h| h >= FIT_MIN_ROWS_WORTH_FITTING)
    } else {
        None
    }
}

fn stdout_terminal_width() -> Option<usize> {
    if std::io::stdout().is_terminal() {
        terminal_size::terminal_size().map(|(w, _)| w.0 as usize)
    } else {
        None
    }
}

fn record_open_failures(failed_sources: usize) {
    if failed_sources != 0 {
        output::record_failure();
    }
}

fn register_input(folder: &mut PatternFolder, source: &ingest::Source) -> Option<SourceId> {
    source
        .file_name()
        .map(|name| folder.register_source(name.to_string()))
}

fn open_report_or_exit(plan: &cli::ReportPlan) -> Option<lessence::report::Spool> {
    match plan {
        cli::ReportPlan::Off => None,
        cli::ReportPlan::On(settings) => match open_spool(settings) {
            Ok(spool) => Some(spool),
            Err(e) => {
                eprintln!(
                    "lessence: report: not written ({e})\n\
                     lessence: pass --report-dir DIR to choose another location, or --no-report to \
                     fold without saving one"
                );
                std::process::exit(1);
            }
        },
    }
}

fn abort_report(spool: &mut lessence::report::Spool, lines_proved: usize, e: &anyhow::Error) -> ! {
    spool.discard_partial();
    eprintln!("lessence: report: not written ({e})");
    eprintln!(
        "lessence: briefing: input incomplete (aborted at line {lines_proved}), report removed"
    );
    std::process::exit(1);
}

fn main() -> Result<()> {
    let matches = cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let format_given = matches.value_source("format") == Some(ValueSource::CommandLine);

    reject_report_flags_outside_fold(&cli);
    if let Some(done) = early_dispatch(&cli) {
        return done;
    }

    if nothing_to_fold(&cli) {
        cli::command().print_help()?;
        return Ok(());
    }

    let distilling = cli.distilling();
    if distilling && let Err(e) = cli.validate_distill() {
        exit_usage_error(e);
    }
    if let Err(e) = cli.validate_preflight() {
        exit_usage_error(e);
    }

    let requested_format = cli::validate_format(if cli.json { "json" } else { &cli.format })
        .unwrap_or_else(|e| exit_usage_error(e));
    let requested_format = resolve_explain_format(&cli, requested_format, format_given);
    if let Err(e) = cli.validate_markdown(requested_format) {
        exit_usage_error(e);
    }

    let saves_report = requested_format == OutputFormat::Text
        && !cli.summary
        && cli.top.is_none()
        && !cli.fit
        && !cli.preflight
        && !cli.explain
        && !distilling;
    let report_plan = cli
        .report_plan(if saves_report {
            RunShape::DefaultTextRun
        } else {
            RunShape::OtherRun
        })
        .unwrap_or_else(|e| exit_usage_error(e));
    let format = report_plan.rendered_format(requested_format);

    let summary_mode = resolve_summary_mode(&cli, format);
    let json_summary_default_cap = matches!(
        summary_mode,
        SummaryMode::JsonTopN {
            capped_by_default: true
        }
    );
    let effective_top = cli
        .top
        .or(matches!(summary_mode, SummaryMode::JsonTopN { .. })
            .then_some(config::DEFAULT_SUMMARY_TOP));

    let sanitizer = lessence::sanitize::Sanitizer::parse(&cli.sanitize, cli.sanitize_pii)
        .unwrap_or_else(|e| exit_usage_error(e));
    let mut config = Config {
        threshold: cli.threshold,
        min_collapse: cli.min_collapse,
        output_format: format,
        stats: !cli.no_stats,
        preserve_color: cli.preserve_color,
        preflight: cli.preflight,
        summary: matches!(summary_mode, SummaryMode::Text),
        essence_mode: cli.essence,
        thread_count: cli.threads,
        max_line_length: cli
            .max_line_length
            .or(Some(config::DEFAULT_MAX_LINE_LENGTH)),
        max_lines: cli.max_lines,
        sanitize_pii: sanitizer.is_some(),
        sanitize: sanitizer,
        top_n: effective_top,
        stats_json: cli.stats_json,
        fail_pattern: cli.fail_on_pattern.clone(),
        frame_continuations: cli.frame_continuations,
        explain: cli.explain,
        group_sink: if distilling {
            GroupSink::RecordDistillMembers {
                members_per_group: cli.members,
            }
        } else {
            GroupSink::Render
        },
        ..Config::default()
    };
    for name in &cli.disable_patterns {
        let known = config.set_pattern_enabled(name, false);
        debug_assert!(
            known,
            "clap's value parser admits only registered pattern names, not {name}"
        );
    }
    config.keep_sanitized_detectors();
    let config = config;

    let fit_budget = fit_budget(&cli);

    let ingestor = Ingestor::from_config(&config).unwrap_or_else(|e| exit_usage_error(e));

    let start_time = Instant::now();

    let use_json_output = config.output_format == OutputFormat::Json;

    let ingest::OpenedInputs {
        readers,
        failed_opens: failed_sources,
    } = ingest::open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }
    record_open_failures(failed_sources);

    let ingestor = ingestor.with_input_hash_if_every_input_opened(
        (use_json_output || config.preflight)
            && !distilling
            && !config.sanitize_pii
            && config.sanitize.is_none(),
        failed_sources,
    );

    if distilling {
        let opts = lessence::distill::Options::from_flags(
            cli.distill,
            cli.anonymize,
            cli.anonymize_words.clone(),
            cli.seed,
        );
        let outcome =
            lessence::distill::distill_and_self_check(&config, &ingestor, readers, &opts)?;
        std::process::exit(if failed_sources != 0 {
            1
        } else {
            outcome.exit_code()
        });
    }

    if config.preflight {
        let mut folder = PatternFolder::new(config.clone());
        let ingest_report = ingestor.run(readers, |event| {
            match event {
                Event::BeginInput { source } => {
                    register_input(&mut folder, source);
                }
                Event::Line { text, .. } => {
                    folder.process_line(text)?;
                }
            }
            Ok(())
        })?;
        folder.drain_into_briefing()?;

        folder.absorb_ingest_report(&ingest_report, failed_sources);
        if ingest_report.fail_pattern_matched {
            output::record_failure();
        }

        let mut preflight = Vec::new();
        folder.print_preflight_json(&mut preflight)?;
        write_or_exit_on_closed_pipe(
            &mut io::stdout(),
            format_args!("{}", String::from_utf8(preflight)?),
        )?;
        if ingest_report.fail_pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut folder = PatternFolder::new(config.clone());

    if config.summary {
        let ingest_report = ingestor.run(readers, |event| {
            if let Event::Line { text, .. } = event {
                folder.process_line(text)?;
            }
            Ok(())
        })?;
        if ingest_report.fail_pattern_matched {
            output::record_failure();
        }
        folder.finish_summary(
            &SummaryRequest {
                top_n: config.top_n,
                fit_budget,
                max_width: stdout_terminal_width(),
            },
            &ingest_report,
            failed_sources,
            &mut io::stdout().lock(),
            &mut io::stderr(),
        )?;
        if config.stats_json {
            folder.print_stats_json(start_time.elapsed(), &mut io::stderr().lock())?;
        }
        if ingest_report.fail_pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut spool = open_report_or_exit(&report_plan);

    let mut stdout = io::stdout();
    let mut source_for_json_records = None;
    let mut lines_proved = 0usize;
    let ingest_result = ingestor.run(readers, |event| {
        match event {
            Event::BeginInput { source } => {
                source_for_json_records = register_input(&mut folder, source);
            }
            Event::Line { text, line_number } => {
                lines_proved = line_number.get();
                if use_json_output {
                    folder.process_line_at(text, source_for_json_records, line_number.get())?;
                } else {
                    folder.process_line(text)?;
                }
            }
        }
        Ok(())
    });
    let ingest_report = match ingest_result {
        Ok(report) => report,
        Err(e) => {
            if let Some(spool) = spool.as_mut() {
                abort_report(spool, lines_proved, &e);
            }
            return Err(e);
        }
    };
    folder.absorb_ingest_report(&ingest_report, failed_sources);
    let pattern_matched = ingest_report.fail_pattern_matched;
    if pattern_matched {
        output::record_failure();
    }

    if let Some(n) = config.top_n {
        let lessence::folder::TopGroups {
            shown: groups_to_show,
            total_groups,
            coverage_pct,
            fit_truncated,
        } = folder.finish_top_n(n, fit_budget, json_summary_default_cap)?;
        let json_output = use_json_output;

        for (count, formatted) in &groups_to_show {
            if json_output {
                write_or_exit_on_closed_pipe(&mut stdout, format_args!("{formatted}\n"))?;
            } else {
                write_or_exit_on_closed_pipe(
                    &mut stdout,
                    format_args!("[{count}x] {formatted}\n"),
                )?;
            }
        }
        if fit_truncated > 0 {
            if json_output {
                eprintln!("lessence: {fit_truncated} more patterns omitted by --fit");
            } else {
                let _ = writeln!(
                    stdout,
                    "... {fit_truncated} more patterns (remove --fit for full output)"
                );
            }
        }
        let shown = groups_to_show.len();
        eprintln!(
            "(showing top {shown} of {total_groups} patterns, covering {coverage_pct}% of input lines)"
        );

        print_run_trailer(&folder, &config, start_time.elapsed(), json_output)?;
        if pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Some(spool) = spool.take() {
        let cli::ReportPlan::On(settings) = &report_plan else {
            unreachable!("a spool exists only when the report plan is On")
        };
        finish_report(
            &mut folder,
            &config,
            spool,
            settings,
            start_time.elapsed(),
            pattern_matched || failed_sources != 0,
        )?;
        return Ok(());
    }

    if config.output_format == OutputFormat::Markdown {
        let entries = folder.finish_markdown()?;
        folder.emit_markdown(&entries, &mut io::stdout())?;
        if pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    for output in folder.finish()? {
        write_or_exit_on_closed_pipe(&mut stdout, format_args!("{output}\n"))?;
    }

    print_run_trailer(&folder, &config, start_time.elapsed(), use_json_output)?;

    if pattern_matched || failed_sources != 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn open_spool(settings: &cli::ReportSettings) -> Result<lessence::report::Spool> {
    use lessence::report::{self, DEFAULT_PER_RUN_MAX_BYTES};

    let (dir, placement) = report::resolve_dir(settings.dir.as_deref())?;
    let explicit_positive_quota_given = settings.max_bytes.is_some_and(|n| n > 0);
    report::check_filesystem(&dir, placement.policy(explicit_positive_quota_given))?;
    let max_bytes = settings
        .max_bytes
        .map_or(DEFAULT_PER_RUN_MAX_BYTES, |n| n as u64);
    let mut spool = report::Spool::create(&dir, max_bytes)?;
    if let lessence::overview::Entries::Count(n) = settings.entries {
        spool.index_for_overview(n);
    }
    Ok(spool)
}

fn finish_report(
    folder: &mut PatternFolder,
    config: &Config,
    mut spool: lessence::report::Spool,
    settings: &cli::ReportSettings,
    elapsed: Duration,
    already_failing: bool,
) -> Result<()> {
    let mut complete = || -> Result<lessence::report::Finished> {
        for output in folder.finish()? {
            spool.write_record(&output)?;
        }
        let mut summary = Vec::new();
        folder.print_summary_json(&mut summary, elapsed)?;
        let summary = String::from_utf8(summary)?;
        spool.write_record(summary.trim_end_matches('\n'))?;
        spool.finish()
    };
    let durability = match complete() {
        Ok(durability) => durability,
        Err(e) => {
            spool.discard_partial();
            eprintln!("lessence: report: not written ({e})");
            eprintln!(
                "lessence: briefing: input {}",
                lessence::overview::InputState::from_degraded_codes(folder.input_degraded_codes())
            );
            if config.stats && !config.stats_json {
                folder.print_stats(&mut io::stderr())?;
            }
            std::process::exit(1);
        }
    };

    let index = spool.take_index();
    let failed = already_failing || durability.is_durability_unconfirmed();
    let locator = lessence::overview::Locator {
        path: spool.final_path(),
        file: durability,
        input: lessence::overview::InputState::from_degraded_codes(folder.input_degraded_codes()),
        run_id: spool.run_id(),
        size_bytes: spool.bytes_written(),
    };

    if config.stats_json {
        folder.print_stats_json(elapsed, &mut io::stderr().lock())?;
    }
    let briefing = if config.stats && !config.stats_json {
        let mut buf = Vec::new();
        folder.print_stats(&mut buf)?;
        Some(String::from_utf8(buf)?)
    } else {
        None
    };

    #[cfg(feature = "test-hooks")]
    truncate_report_for_test(&spool)?;

    let mut stdout = lessence::output::ClosedPipeIsEarlyStop::new(io::stdout());
    let result = lessence::overview::render(
        &mut stdout,
        spool.final_path(),
        &locator,
        settings.entries,
        settings.budget,
        briefing.as_deref(),
        index,
    );
    match result {
        Ok(()) => {
            stdout.flush()?;
            if failed {
                std::process::exit(1);
            }
            Ok(())
        }
        Err(e) => {
            stdout
                .write_all(lessence::overview::unavailable(&locator, &e.to_string()).as_bytes())?;
            stdout.flush()?;
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "test-hooks")]
fn truncate_report_for_test(spool: &lessence::report::Spool) -> Result<()> {
    if let Ok(bytes) = std::env::var("LESSENCE_TEST_TRUNCATE_REPORT")
        && let Ok(bytes) = bytes.parse::<u64>()
    {
        std::fs::OpenOptions::new()
            .write(true)
            .open(spool.final_path())?
            .set_len(bytes)?;
    }
    Ok(())
}

fn print_run_trailer(
    folder: &PatternFolder,
    config: &Config,
    elapsed: Duration,
    json_output: bool,
) -> Result<()> {
    if json_output {
        let mut record = Vec::new();
        folder.print_summary_json(&mut record, elapsed)?;
        write_or_exit_on_closed_pipe(
            &mut io::stdout(),
            format_args!("{}", String::from_utf8(record)?),
        )?;
        if config.stats_json {
            eprintln!(
                "lessence: --stats-json ignored in JSON mode (summary record already emitted)"
            );
        }
    } else if config.stats_json {
        folder.print_stats_json(elapsed, &mut io::stderr().lock())?;
    } else if config.stats {
        folder.print_stats(&mut io::stderr())?;
    }
    Ok(())
}
