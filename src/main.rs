use anyhow::Result;
use clap::Parser;
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

use lessence::cli::{self, Cli};
use lessence::config::{self, Config};
use lessence::folder::PatternFolder;
use lessence::ingest::{self, Event, Ingestor};
use lessence::output::write_output;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // The early and dev dispatches below return before the fold is
    // configured, so the report flags are validated here rather than after
    // them: `--diff OLD --report-dir DIR` is a usage error, not a silently
    // ignored flag.
    if (cli.help_human || cli.skill.is_some() || cli.completions.is_some() || cli.diff.is_some())
        && let Err(e) = cli.report_plan(false)
    {
        eprintln!("lessence: {e}");
        std::process::exit(2);
    }

    // --help-human is the one help written for a person; it exits before
    // any input is opened, like --skill.
    if cli.help_human {
        io::stdout().write_all(cli::HELP_HUMAN.as_bytes())?;
        return Ok(());
    }

    // --skill prints the bundled agent skill and exits before any input is
    // opened, so `lessence --skill > file` never waits on stdin.
    if let Some(topic) = &cli.skill {
        let Some(text) = lessence::skill::render(topic, cli::VERSION) else {
            eprintln!(
                "lessence: unknown --skill topic '{topic}' (expected one of: {})",
                lessence::skill::TOPICS.join(", ")
            );
            std::process::exit(2);
        };
        io::stdout().write_all(text.as_bytes())?;
        return Ok(());
    }

    // Handle --completions before anything else
    if let Some(shell) = cli.completions {
        let mut cmd = cli::command();
        clap_complete::generate(shell, &mut cmd, "lessence", &mut io::stdout());
        return Ok(());
    }

    // --diff is a comparison of two binaries' output, not a fold of its own.
    // Everything below configures a fold, so it dispatches out here.
    if let Some(other) = &cli.diff {
        let me = std::env::current_exe()?;
        let moved = lessence::diff::run(other, &me, &cli.files, "1")?;
        std::process::exit(i32::from(moved > 0));
    }

    // Nothing to fold: no file and a terminal on stdin. Waiting silently for
    // input looks like a hang to a person and is one for an agent, so show
    // the help instead. A pipe, a file, or an explicit `-` still folds.
    if cli.files.is_empty() && io::stdin().is_terminal() {
        cli::command().print_help()?;
        return Ok(());
    }

    // --distill / --anonymize write a log rather than a report, so they
    // reject the output-mode flags instead of ignoring them.
    let distilling = cli.distill || cli.anonymize || cli.anonymize_words.is_some();
    if distilling && let Err(e) = cli.validate_distill() {
        eprintln!("lessence: {e}");
        std::process::exit(2);
    }

    // Validate output format before creating config; downstream dispatch
    // compares against the canonical spelling this returns.
    let mut format = cli::validate_format(if cli.json { "json" } else { &cli.format })?;
    // --explain annotates the JSON group records; there is nothing to
    // annotate in the other formats.
    if cli.explain && !matches!(format.as_str(), "json" | "jsonl") {
        format = "json".to_string();
    }

    // --format markdown renders only the default fold output. These
    // combinations used to fall back to plain text silently; agents
    // prefer a loud error over silently-wrong output.
    if format == "markdown" && (cli.top.is_some() || cli.summary || cli.fit || cli.preflight) {
        eprintln!(
            "lessence: --format markdown supports only the default fold output; \
             drop --top/--summary/--fit/--preflight or use --format text or json"
        );
        std::process::exit(2);
    }

    // The default text run — no --format other than text and none of the
    // alternate output or dev modes — is the only run that saves a report.
    // Every report flag outside it is a usage error, never silently ignored.
    let text_default = format == "text"
        && !cli.summary
        && cli.top.is_none()
        && !cli.fit
        && !cli.preflight
        && !cli.explain
        && !distilling;
    let report_plan = match cli.report_plan(text_default) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("lessence: {e}");
            std::process::exit(2);
        }
    };
    // The report is the schema-1 JSON stream of this run, produced by the
    // same renderer as --format json with the same options — that is what
    // makes inventory, representative and metadata parity hold by
    // construction rather than by a second implementation.
    if matches!(report_plan, cli::ReportPlan::On(_)) {
        format = "json".to_string();
    }

    let requested_summary = cli.summary || (cli.fit && cli.top.is_none() && !cli.preflight);
    let json_summary = requested_summary && matches!(format.as_str(), "json" | "jsonl");
    let json_summary_default_cap = json_summary && cli.top.is_none();
    // JSON summary uses the regular JSONL group schema with the summary-mode
    // default cap. This keeps every flag combination machine-parseable.
    let effective_summary = requested_summary && !json_summary;
    let effective_top = cli.top.or(json_summary.then_some(30));

    // Detector gates start at their defaults (all enabled); each
    // --disable-patterns name expands through config::PATTERN_REGISTRY.
    let sanitizer = match lessence::sanitize::Sanitizer::parse(&cli.sanitize, cli.sanitize_pii) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("lessence: {e}");
            std::process::exit(2);
        }
    };
    let mut config = Config {
        threshold: cli.threshold,
        min_collapse: cli.min_collapse,
        output_format: format,
        stats: !cli.no_stats, // Default true unless explicitly disabled
        preserve_color: cli.preserve_color,
        preflight: cli.preflight,
        summary: effective_summary,
        essence_mode: cli.essence,
        thread_count: cli.threads,
        // Security & ReDoS protection flags
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
        // Set for --anonymize too: that mode emits every line, but it still
        // checks its output against the input's templates, and the folder is
        // where those come from.
        distill: distilling.then_some(cli.members),
        ..Config::default()
    };
    for name in &cli.disable_patterns {
        // clap's value_parser has already validated every name
        config.set_pattern_enabled(name, false);
    }
    let config = config;

    // --fit: compute line budget from terminal height (None when piped)
    let fit_budget: Option<usize> = if cli.fit && std::io::stdout().is_terminal() {
        terminal_size::terminal_size()
            .map(|(_, h)| (h.0 as usize).saturating_sub(4)) // command + stderr footer + prompt + buffer
            .filter(|&h| h >= 3) // below 3 rows, just show everything
    } else {
        None
    };

    // The shared ingestion contract: limits, fail-on-pattern (exit 2 on an
    // invalid regex), escape stripping. All three modes below read through it.
    let ingestor = match Ingestor::from_config(&config) {
        Ok(ingestor) => ingestor,
        Err(e) => {
            eprintln!("lessence: {e}");
            std::process::exit(2);
        }
    };

    let start_time = Instant::now();

    let use_json_output = matches!(config.output_format.as_str(), "json" | "jsonl");
    let use_top_n = config.top_n.is_some();

    let (readers, failed_sources) = ingest::open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }

    let ingestor = ingestor.with_input_hash(
        (use_json_output || config.preflight)
            && !distilling
            && !config.sanitize_pii
            && config.sanitize.is_none()
            && failed_sources == 0,
    );

    if distilling {
        let opts = lessence::distill::Options {
            distill: cli.distill,
            members: cli.members,
            // A vocabulary with nothing to anonymise would be a no-op the
            // caller could not see; asking for words asks for anonymisation.
            anonymize: cli.anonymize || cli.anonymize_words.is_some(),
            words_file: cli.anonymize_words.clone(),
            seed: cli.seed,
        };
        let code = lessence::distill::run(&config, &ingestor, readers, &opts)?;
        std::process::exit(if failed_sources != 0 { 1 } else { code });
    }

    // Handle preflight mode: process logs but only output JSON analysis
    if config.preflight {
        let mut folder = PatternFolder::new(config.clone());
        // Process all lines but don't output log content. The briefing's
        // `source` field still needs the input filename, so BeginInput is
        // registered even though nothing else here is JSON-output-gated.
        let ingest_report = ingestor.run(readers, |event| {
            match event {
                Event::BeginInput { source } => {
                    if let Some(source) = source {
                        folder.register_source(source.to_string());
                    }
                }
                Event::Line { text, .. } => {
                    folder.process_line(text)?;
                }
            }
            Ok(())
        })?;
        // Flush remaining batch buffer (parallel mode collects lines in batches)
        let _ = folder.finish()?;

        folder.record_ingest_metadata(&ingest_report, failed_sources);

        // Output JSON analysis only
        folder.print_preflight_json(&mut io::stdout())?;
        if ingest_report.fail_pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut folder = PatternFolder::new(config.clone());

    // Handle summary mode: use normal parallel pipeline, then output as summary
    if config.summary {
        let ingest_report = ingestor.run(readers, |event| {
            if let Event::Line { text, .. } = event {
                folder.process_line(text)?;
            }
            Ok(())
        })?;
        // Flush and output as summary (one line per group, sorted by count)
        folder.finish_summary(config.top_n, fit_budget)?;
        if config.stats_json {
            folder.print_stats_json(start_time.elapsed())?;
        }
        if ingest_report.fail_pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Open the report before a single line is read: a directory or file
    // failure here leaves nothing on disk and ends the run.
    let mut spool = match &report_plan {
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
    };

    let mut stdout = io::stdout();
    // Provenance handle for the input currently yielding lines; only the
    // JSON path pays the source-registration cost.
    let mut current_source_id = None;
    // The last line the ingest actually proved, for the truthful `input:
    // incomplete (aborted at line N)` state when the spool fails mid-run.
    let mut lines_proved = 0usize;
    let ingest_result = ingestor.run(readers, |event| {
        match event {
            Event::BeginInput { source } => {
                // Registered unconditionally, not just in JSON mode: the
                // briefing's `source` field (text footer, --preflight,
                // --explain) needs the filename too. `current_source_id`
                // itself is only consumed by `process_line_at` below.
                current_source_id = source.map(|source| folder.register_source(source.to_string()));
            }
            Event::Line { text, line_number } => {
                lines_proved = line_number;
                let output = if use_json_output {
                    folder.process_line_at(text, current_source_id, line_number)?
                } else {
                    folder.process_line(text)?
                };

                if let Some(output) = output {
                    if use_top_n {
                        // In top-N mode, discard incremental output — we'll use finish_top_n()
                    } else if let Some(spool) = spool.as_mut() {
                        spool.write_record(&output)?;
                    } else {
                        write_output(&mut stdout, format_args!("{output}\n"))?;
                    }
                }
            }
        }
        Ok(())
    });
    let ingest_report = match ingest_result {
        Ok(report) => report,
        Err(e) => {
            // Either a fatal read/UTF-8 error or a spool failure mid-run.
            // Both abort ingestion before EOF, so the report can never be
            // completed and the briefing must say the input is incomplete.
            if let Some(spool) = spool.as_mut() {
                spool.discard();
                eprintln!("lessence: report: not written ({e})");
                // No template statistics: the ingest stopped before EOF, so
                // the counts a briefing rests on were never established.
                eprintln!(
                    "lessence: briefing: input incomplete (aborted at line {lines_proved}), report removed"
                );
                std::process::exit(1);
            }
            return Err(e);
        }
    };
    folder.absorb_ingest_report(&ingest_report, failed_sources);
    let pattern_matched = ingest_report.fail_pattern_matched;

    // Handle top-N mode: sort all groups by frequency and emit top N
    if let Some(n) = config.top_n {
        let (groups_to_show, total_groups, coverage_pct, fit_truncated) =
            folder.finish_top_n(n, fit_budget, json_summary_default_cap)?;
        let json_output = use_json_output;

        for (count, formatted) in &groups_to_show {
            if json_output {
                write_output(&mut stdout, format_args!("{formatted}\n"))?;
            } else {
                write_output(&mut stdout, format_args!("[{count}x] {formatted}\n"))?;
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

        print_report_stats(&folder, &config, start_time.elapsed(), json_output)?;
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

    // Flush any remaining buffered lines (markdown mode buffers them in
    // the folder instead and emits one assembled document below)
    for output in folder.finish()? {
        write_output(&mut stdout, format_args!("{output}\n"))?;
    }

    // Markdown: emit one assembled document from the buffered entries
    if config.output_format.as_str() == "markdown" {
        folder.emit_markdown(&mut io::stdout())?;
        if pattern_matched || failed_sources != 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    print_report_stats(&folder, &config, start_time.elapsed(), use_json_output)?;

    if pattern_matched || failed_sources != 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Resolve the report directory, apply the filesystem policy, and open the
/// spool. Every failure here happens before any input is read.
fn open_spool(settings: &cli::ReportSettings) -> Result<lessence::report::Spool> {
    use lessence::report::{self, DEFAULT_MAX_BYTES};

    let (dir, placement) = report::resolve_dir(settings.dir.as_deref())?;
    // The bounded, acknowledged exception: an explicit directory together
    // with an explicit positive quota accepts any filesystem.
    let bounded = settings.max_bytes.is_some_and(|n| n > 0);
    report::check_filesystem(&dir, placement, bounded)?;
    let max_bytes = settings.max_bytes.map_or(DEFAULT_MAX_BYTES, |n| n as u64);
    report::Spool::create(&dir, max_bytes)
}

/// Complete the report — drain, summary record, flush, fsync, rename,
/// directory fsync — then print the bounded overview of the finished file.
///
/// Truthful state on every failure: what is said about the file is what is
/// on disk, and what is said about the input is what the ingest proved.
/// Reaching here means EOF was reached, so the input is `complete` or
/// `degraded(<codes>)`, never `incomplete`.
fn finish_report(
    folder: &mut PatternFolder,
    config: &Config,
    mut spool: lessence::report::Spool,
    settings: &cli::ReportSettings,
    elapsed: Duration,
    already_failing: bool,
) -> Result<()> {
    let mut complete = || -> Result<Option<String>> {
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
            // Nothing was renamed, so nothing on disk is a report.
            spool.discard();
            eprintln!("lessence: report: not written ({e})");
            let codes = folder.input_degraded_codes();
            eprintln!(
                "lessence: briefing: input {}",
                if codes.is_empty() {
                    "complete".to_string()
                } else {
                    format!("degraded({})", codes.join(","))
                }
            );
            if config.stats && !config.stats_json {
                folder.print_stats(&mut io::stderr())?;
            }
            std::process::exit(1);
        }
    };

    let codes = folder.input_degraded_codes();
    let locator = lessence::overview::Locator {
        path: spool.final_path(),
        file: durability.as_ref().map_or_else(
            || "complete".to_string(),
            |e| format!("complete, durability unconfirmed ({e})"),
        ),
        input: if codes.is_empty() {
            "complete".to_string()
        } else {
            format!("degraded({})", codes.join(","))
        },
        run_id: spool.run_id(),
        size_bytes: spool.bytes_written(),
    };

    // --stats-json keeps going to stderr, as today, in addition to the
    // overview; -q (config.stats false) drops the briefing block.
    if config.stats_json {
        folder.print_stats_json(elapsed)?;
    }
    let briefing = if config.stats && !config.stats_json {
        let mut buf = Vec::new();
        folder.print_stats(&mut buf)?;
        Some(String::from_utf8(buf)?)
    } else {
        None
    };

    // Failure-injection seam for the overview pass, alongside the writer
    // and directory-fsync seams in src/report.rs. Compiled in only under
    // the `test-hooks` feature, which the self dev-dependency turns on for
    // `cargo test` and which no distributed build ever enables: nothing
    // here can truncate a caller's completed report.
    #[cfg(feature = "test-hooks")]
    if let Ok(bytes) = std::env::var("LESSENCE_TEST_TRUNCATE_REPORT")
        && let Ok(bytes) = bytes.parse::<u64>()
    {
        std::fs::OpenOptions::new()
            .write(true)
            .open(spool.final_path())?
            .set_len(bytes)?;
    }

    // A consumer closing stdout is an early stop, never a verdict: the
    // report is already on disk, and an exit code this run has already
    // determined survives the broken pipe.
    let mut stdout = lessence::output::PipeTolerant::new(io::stdout());
    let failed = already_failing || durability.is_some();
    let result = lessence::overview::render(
        &mut stdout,
        spool.final_path(),
        &locator,
        settings.entries,
        settings.budget,
        briefing.as_deref(),
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
            // The report is complete and stays. No group is silently
            // omitted: stdout names why the overview could not be built.
            stdout
                .write_all(lessence::overview::unavailable(&locator, &e.to_string()).as_bytes())?;
            stdout.flush()?;
            std::process::exit(1);
        }
    }
}

/// JSON reports always end with a summary record; text reports choose
/// JSON stats, the human briefing, or silence according to the stats flags.
fn print_report_stats(
    folder: &PatternFolder,
    config: &Config,
    elapsed: Duration,
    json_output: bool,
) -> Result<()> {
    if json_output {
        folder.print_summary_json(&mut io::stdout(), elapsed)?;
        if config.stats_json {
            eprintln!(
                "lessence: --stats-json ignored in JSON mode (summary record already emitted)"
            );
        }
    } else if config.stats_json {
        folder.print_stats_json(elapsed)?;
    } else if config.stats {
        folder.print_stats(&mut io::stderr())?;
    }
    Ok(())
}
