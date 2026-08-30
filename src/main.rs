use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::time::Instant;

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

fn main() -> Result<()> {
    let cli = Cli::parse();

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

    // --distill / --anonymize write a log rather than a report, so they
    // reject the output-mode flags instead of ignoring them.
    let distilling = cli.distill || cli.anonymize || cli.anonymize_words.is_some();
    if distilling && let Err(e) = cli.validate_distill() {
        eprintln!("lessence: {e}");
        std::process::exit(2);
    }

    // Validate output format before creating config; downstream dispatch
    // compares against the canonical spelling this returns.
    let mut format = cli::validate_format(&cli.format)?;
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

    let requested_summary = cli.summary || (cli.fit && cli.top.is_none() && !cli.preflight);
    let json_summary = requested_summary && matches!(format.as_str(), "json" | "jsonl");
    let json_summary_default_cap = json_summary && cli.top.is_none();
    // JSON summary uses the regular JSONL group schema with the summary-mode
    // default cap. This keeps every flag combination machine-parseable.
    let effective_summary = requested_summary && !json_summary;
    let effective_top = cli.top.or(json_summary.then_some(30));

    // Detector gates start at their defaults (all enabled); each
    // --disable-patterns name expands through config::PATTERN_REGISTRY.
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
        sanitize_pii: cli.sanitize_pii, // Wire PII sanitization flag
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

    let (readers, input_failed) = ingest::open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }

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
        std::process::exit(if input_failed { 1 } else { code });
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

        // Output JSON analysis only
        folder.print_preflight_json(&mut io::stdout())?;
        if ingest_report.fail_pattern_matched || input_failed {
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
        if ingest_report.fail_pattern_matched || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut stdout = io::stdout();
    // Provenance handle for the input currently yielding lines; only the
    // JSON path pays the source-registration cost.
    let mut current_source_id = None;
    let ingest_report = ingestor.run(readers, |event| {
        match event {
            Event::BeginInput { source } => {
                // Registered unconditionally, not just in JSON mode: the
                // briefing's `source` field (text footer, --preflight,
                // --explain) needs the filename too. `current_source_id`
                // itself is only consumed by `process_line_at` below.
                current_source_id = source.map(|source| folder.register_source(source.to_string()));
            }
            Event::Line { text, line_number } => {
                let output = if use_json_output {
                    folder.process_line_at(text, current_source_id, line_number)?
                } else {
                    folder.process_line(text)?
                };

                if let Some(output) = output {
                    if use_top_n {
                        // In top-N mode, discard incremental output — we'll use finish_top_n()
                    } else {
                        match writeln!(stdout, "{output}") {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                                std::process::exit(0);
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
        }
        Ok(())
    })?;
    folder.absorb_ingest_report(&ingest_report, input_failed);
    let pattern_matched = ingest_report.fail_pattern_matched;

    // Handle top-N mode: sort all groups by frequency and emit top N
    if let Some(n) = config.top_n {
        let (groups_to_show, total_groups, coverage_pct, fit_truncated) =
            folder.finish_top_n(n, fit_budget, json_summary_default_cap)?;
        let json_output = use_json_output;

        for (count, formatted) in &groups_to_show {
            let result = if json_output {
                writeln!(stdout, "{formatted}")
            } else {
                writeln!(stdout, "[{count}x] {formatted}")
            };
            match result {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                }
                Err(e) => return Err(e.into()),
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

        if json_output {
            folder.print_summary_json(&mut stdout, start_time.elapsed())?;
            if config.stats_json {
                eprintln!(
                    "lessence: --stats-json ignored in JSON mode (summary record already emitted)"
                );
            }
        } else if config.stats_json {
            folder.print_stats_json(start_time.elapsed())?;
        } else if config.stats {
            folder.print_stats(&mut io::stderr())?;
        }
        if pattern_matched || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Flush any remaining buffered lines (markdown mode buffers them in
    // the folder instead and emits one assembled document below)
    for output in folder.finish()? {
        match writeln!(stdout, "{output}") {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                std::process::exit(0);
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Markdown: emit one assembled document from the buffered entries
    if config.output_format.as_str() == "markdown" {
        folder.emit_markdown(&mut io::stdout())?;
        if pattern_matched || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    // JSON mode: emit the terminal summary record, then skip the
    // human/--stats-json paths (the summary record supersedes them).
    if use_json_output {
        folder.print_summary_json(&mut io::stdout(), start_time.elapsed())?;
        if config.stats_json {
            eprintln!(
                "lessence: --stats-json ignored in JSON mode (summary record already emitted)"
            );
        }
        if pattern_matched || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    if config.stats_json {
        folder.print_stats_json(start_time.elapsed())?;
    } else if config.stats {
        folder.print_stats(&mut io::stderr())?;
    }

    if pattern_matched || input_failed {
        std::process::exit(1);
    }

    Ok(())
}
