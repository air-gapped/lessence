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

mod analyzer;
mod cli;
mod config;
mod folder;
mod ingest;
mod normalize;
mod output;
mod patterns;
mod report;

use analyzer::LogAnalyzer;
use cli::Cli;
use config::Config;
use folder::PatternFolder;
use ingest::{Event, Ingestor};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --completions before anything else
    if let Some(shell) = cli.completions {
        let mut cmd = cli::command();
        clap_complete::generate(shell, &mut cmd, "lessence", &mut io::stdout());
        return Ok(());
    }

    // Validate output format before creating config
    cli.format.parse::<output::OutputFormat>()?;

    // --format markdown renders only the default fold output. These
    // combinations used to fall back to plain text silently; agents
    // prefer a loud error over silently-wrong output.
    if cli.format == "markdown" && (cli.top.is_some() || cli.summary || cli.fit || cli.preflight) {
        eprintln!(
            "lessence: --format markdown supports only the default fold output; \
             drop --top/--summary/--fit/--preflight or use --format text or json"
        );
        std::process::exit(2);
    }

    let requested_summary = cli.summary || (cli.fit && cli.top.is_none() && !cli.preflight);
    let json_summary = requested_summary && matches!(cli.format.as_str(), "json" | "jsonl");
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
        output_format: cli.format,
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

    // Handle preflight mode: process logs but only output JSON analysis
    if config.preflight {
        let mut folder = PatternFolder::new(config.clone());
        // Process all lines but don't output log content
        let ingest_report = ingestor.run(readers, |event| {
            if let Event::Line { text, .. } = event {
                folder.process_line(text)?;
            }
            Ok(())
        })?;
        // Flush remaining batch buffer (parallel mode collects lines in batches)
        let _ = folder.finish()?;

        // Output JSON analysis only
        let analysis = LogAnalyzer::from_folder_stats(&folder, &config)?;
        let json_output = serde_json::to_string_pretty(&analysis)?;
        println!("{json_output}");
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

    if input_failed && use_json_output {
        folder.note_input_source_failed();
    }
    let mut stdout = io::stdout();
    // Provenance handle for the input currently yielding lines; only the
    // JSON path pays the source-registration cost.
    let mut current_source_id = None;
    let ingest_report = ingestor.run(readers, |event| {
        match event {
            Event::BeginInput { source } => {
                current_source_id = if use_json_output {
                    source.map(|source| folder.register_source(source.to_string()))
                } else {
                    None
                };
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
                            Ok(_) => {
                                if use_json_output {
                                    folder.note_json_groups_emitted(1);
                                }
                            }
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
    if use_json_output {
        folder.note_overlong_lines_skipped(ingest_report.overlong_lines_skipped);
        if ingest_report.max_lines_reached {
            folder.note_max_lines_reached();
        }
    }
    let pattern_matched = ingest_report.fail_pattern_matched;

    // Handle top-N mode: sort all groups by frequency and emit top N
    if let Some(n) = config.top_n {
        let previously_omitted_groups = folder.json_groups_formatted();
        let (top_groups, total_groups, coverage_pct) = folder.finish_top_n(n)?;
        let json_output = use_json_output;

        // Apply --fit budget
        let (groups_to_show, fit_truncated) = if let Some(budget) = fit_budget {
            if top_groups.len() > budget {
                let show = budget.saturating_sub(1);
                let remaining = top_groups.len() - show;
                (&top_groups[..show], remaining)
            } else {
                (&top_groups[..], 0)
            }
        } else {
            (&top_groups[..], 0)
        };

        for (count, formatted) in groups_to_show {
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
        if json_output {
            let all_groups = total_groups + previously_omitted_groups;
            let omitted_before_fit = all_groups.saturating_sub(top_groups.len());
            let (top_omitted, summary_omitted) = if json_summary_default_cap {
                (0, omitted_before_fit)
            } else {
                (omitted_before_fit, 0)
            };
            folder.note_json_groups_emitted(shown);
            folder.note_json_group_limits(all_groups, top_omitted, summary_omitted, fit_truncated);
        }
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
            Ok(_) => {
                if use_json_output {
                    folder.note_json_groups_emitted(1);
                }
            }
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
