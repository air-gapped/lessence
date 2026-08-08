use anyhow::Result;
use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::path::PathBuf;
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
mod normalize;
mod output;
mod patterns;
mod report;

use analyzer::LogAnalyzer;
use cli::Cli;
use config::Config;
use folder::PatternFolder;

/// Strip terminal escape sequences and bare control characters from text.
///
/// Delegates to the single shared sanitizer in [`analyzer::strip_terminal_escapes`]
/// so the binary and the analyzer module can never drift apart. This removes
/// CSI, OSC (BEL- or ST-terminated, e.g. window-title and OSC 8 hyperlinks),
/// DCS/APC/PM/SOS, lone ESC, and bare C0 controls (CR/BS/VT/FF) that would
/// otherwise reach the operator's terminal verbatim.
fn strip_ansi_codes(text: &str) -> String {
    analyzer::strip_terminal_escapes(text)
}

/// Wrap untrusted log content in a CommonMark code fence so it cannot inject
/// markdown structure (headings, links, images, raw HTML) when the report is
/// rendered or ingested by an LLM/agent. The fence uses a backtick run one
/// longer than the longest run present in `content` (min 3), so embedded
/// triple-backticks can't close the fence early.
fn markdown_code_fence(content: &str) -> String {
    let mut longest_run = 0usize;
    let mut current_run = 0usize;
    for ch in content.chars() {
        if ch == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let fence = "`".repeat((longest_run + 1).max(3));
    format!("{fence}\n{content}\n{fence}")
}

/// Opens the given input files, falling back to stdin when none are given.
struct InputReader {
    /// The explicit filename as supplied by the user, or None for stdin.
    source: Option<String>,
    reader: Box<dyn BufRead>,
}

/// Returns the successfully opened readers plus whether any file failed to
/// open — like cat/grep, the remaining files are still processed but the
/// process must exit non-zero.
fn open_inputs(files: &[PathBuf]) -> (Vec<InputReader>, bool) {
    if files.is_empty() {
        return (
            vec![InputReader {
                source: None,
                reader: Box::new(BufReader::new(io::stdin().lock())),
            }],
            false,
        );
    }
    let mut readers = Vec::new();
    let mut any_failed = false;
    for path in files {
        if path.as_os_str() == "-" {
            readers.push(InputReader {
                source: None,
                reader: Box::new(BufReader::new(io::stdin().lock())),
            });
        } else {
            match File::open(path) {
                Ok(f) => readers.push(InputReader {
                    source: Some(path.to_string_lossy().into_owned()),
                    reader: Box::new(BufReader::new(f)),
                }),
                Err(e) => {
                    eprintln!("lessence: {}: {}", path.display(), e);
                    any_failed = true;
                }
            }
        }
    }
    (readers, any_failed)
}

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

    let requested_summary = cli.summary || (cli.fit && cli.top.is_none() && !cli.preflight);
    let json_summary = requested_summary && matches!(cli.format.as_str(), "json" | "jsonl");
    let json_summary_default_cap = json_summary && cli.top.is_none();
    // JSON summary uses the regular JSONL group schema with the summary-mode
    // default cap. This keeps every flag combination machine-parseable.
    let effective_summary = requested_summary && !json_summary;
    let effective_top = cli.top.or(json_summary.then_some(30));

    let config = Config {
        threshold: cli.threshold,
        min_collapse: cli.min_collapse,
        normalize_timestamps: !cli.disable_patterns.contains(&"timestamp".to_string()),
        normalize_hashes: !cli.disable_patterns.contains(&"hash".to_string()),
        normalize_ports: !cli.disable_patterns.contains(&"network".to_string()),
        normalize_ips: !cli.disable_patterns.contains(&"network".to_string()),
        normalize_fqdns: !cli.disable_patterns.contains(&"network".to_string()),
        normalize_uuids: !cli.disable_patterns.contains(&"uuid".to_string()),
        normalize_pids: !cli.disable_patterns.contains(&"process".to_string()),
        normalize_emails: !cli.disable_patterns.contains(&"email".to_string()),
        normalize_paths: !cli.disable_patterns.contains(&"path".to_string()),
        normalize_json: !cli.disable_patterns.contains(&"json".to_string()),
        normalize_durations: !cli.disable_patterns.contains(&"duration".to_string()),
        normalize_kubernetes: !cli.disable_patterns.contains(&"kubernetes".to_string()),
        normalize_http_status: !cli.disable_patterns.contains(&"http-status".to_string()),
        normalize_brackets: !cli.disable_patterns.contains(&"brackets".to_string()),
        normalize_key_value: !cli.disable_patterns.contains(&"key-value".to_string()),
        normalize_quoted: !cli.disable_patterns.contains(&"quoted-string".to_string()),
        normalize_names: !cli.disable_patterns.contains(&"name".to_string()),
        output_format: cli.format,
        stats: !cli.no_stats, // Default true unless explicitly disabled
        preserve_color: cli.preserve_color,
        compact: true, // Always compact format (human-readable by default)
        preflight: cli.preflight,
        summary: effective_summary,
        essence_mode: cli.essence,
        thread_count: cli.threads,
        // Security & ReDoS protection flags
        max_line_length: cli.max_line_length.or(Some(1024 * 1024)), // 1MB default
        max_lines: cli.max_lines,
        sanitize_pii: cli.sanitize_pii, // Wire PII sanitization flag
        top_n: effective_top,
        stats_json: cli.stats_json,
        fail_pattern: cli.fail_on_pattern.clone(),
    };

    // --fit: compute line budget from terminal height (None when piped)
    let fit_budget: Option<usize> = if cli.fit && std::io::stdout().is_terminal() {
        terminal_size::terminal_size()
            .map(|(_, h)| (h.0 as usize).saturating_sub(4)) // command + stderr footer + prompt + buffer
            .filter(|&h| h >= 3) // below 3 rows, just show everything
    } else {
        None
    };

    // Compile fail-on-pattern regex early (exit 2 on invalid)
    let fail_regex = config.fail_pattern.as_ref().map(|pat| {
        regex::Regex::new(pat).unwrap_or_else(|e| {
            eprintln!("lessence: invalid regex '{pat}': {e}");
            std::process::exit(2);
        })
    });
    let pattern_matched = std::cell::Cell::new(false);

    let start_time = Instant::now();

    // For Markdown format, we need to process all logs first, then format
    let use_structured_output = matches!(config.output_format.as_str(), "markdown");
    let use_json_output = matches!(config.output_format.as_str(), "json" | "jsonl");
    let use_top_n = config.top_n.is_some();

    // Handle preflight mode: process logs but only output JSON analysis
    if config.preflight {
        let (readers, input_failed) = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        let mut folder = PatternFolder::new(config.clone());
        // Process all lines but don't output log content
        for (lines_processed, line) in readers
            .into_iter()
            .flat_map(|input| input.reader.lines())
            .enumerate()
        {
            let line = line?;

            // Security: Check line count limit
            if let Some(max_lines) = config.max_lines
                && lines_processed >= max_lines
            {
                break;
            }

            // Security: Check line length limit
            if let Some(max_length) = config.max_line_length
                && line.len() > max_length
            {
                continue;
            }

            // Check fail-on-pattern against raw line
            if let Some(ref re) = fail_regex
                && re.is_match(&line)
            {
                pattern_matched.set(true);
            }

            folder.process_line(&line)?;
        }
        // Flush remaining batch buffer (parallel mode collects lines in batches)
        let _ = folder.finish()?;

        // Output JSON analysis only
        let analysis = LogAnalyzer::from_folder_stats(&folder, &config)?;
        let json_output = serde_json::to_string_pretty(&analysis)?;
        println!("{json_output}");
        if pattern_matched.get() || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut folder = PatternFolder::new(config.clone());

    // Handle summary mode: use normal parallel pipeline, then output as summary
    if config.summary {
        let (readers, input_failed) = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        for (lines_processed, line) in readers
            .into_iter()
            .flat_map(|input| input.reader.lines())
            .enumerate()
        {
            let mut line = line?;
            if let Some(max_lines) = config.max_lines
                && lines_processed >= max_lines
            {
                break;
            }
            if let Some(max_length) = config.max_line_length
                && line.len() > max_length
            {
                continue;
            }
            if let Some(ref re) = fail_regex
                && re.is_match(&line)
            {
                pattern_matched.set(true);
            }
            if !config.preserve_color {
                line = strip_ansi_codes(&line);
            }
            folder.process_line(&line)?;
        }
        // Flush and output as summary (one line per group, sorted by count)
        folder.finish_summary(config.top_n, fit_budget)?;
        if config.stats_json {
            folder.print_stats_json(start_time.elapsed())?;
        }
        if pattern_matched.get() || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    let (readers, input_failed) = open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }
    if input_failed && use_json_output {
        folder.note_input_source_failed();
    }
    let mut stdout = io::stdout();
    let mut collected_outputs = Vec::new();
    let mut lines_processed = 0usize;
    'inputs: for input in readers {
        let source_id = if use_json_output {
            input.source.map(|source| folder.register_source(source))
        } else {
            None
        };

        for (source_line_index, line) in input.reader.lines().enumerate() {
            let mut line = line?;

            // Security: Check line count limit
            if let Some(max_lines) = config.max_lines
                && lines_processed >= max_lines
            {
                eprintln!("Line limit of {max_lines} reached, stopping processing");
                if use_json_output {
                    folder.note_max_lines_reached();
                }
                break 'inputs;
            }
            lines_processed += 1;

            // Security: Check line length limit (Constitutional Principle X)
            if let Some(max_length) = config.max_line_length
                && line.len() > max_length
            {
                if use_json_output {
                    folder.note_overlong_line_skipped();
                }
                continue;
            }

            // Check fail-on-pattern against raw line (before normalization)
            if let Some(ref re) = fail_regex
                && re.is_match(&line)
            {
                pattern_matched.set(true);
            }

            // Strip ANSI color codes by default (unless --preserve-color)
            if !config.preserve_color {
                line = strip_ansi_codes(&line);
            }

            let output = if use_json_output {
                folder.process_line_at(&line, source_id, source_line_index + 1)?
            } else {
                folder.process_line(&line)?
            };

            if let Some(output) = output {
                if use_top_n {
                    // In top-N mode, discard incremental output — we'll use finish_top_n()
                } else if use_structured_output {
                    collected_outputs.push(output);
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
        if pattern_matched.get() || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Flush any remaining buffered lines
    for output in folder.finish()? {
        if use_structured_output {
            collected_outputs.push(output);
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

    // Handle structured output formats
    if use_structured_output {
        let stats = folder.get_stats();
        let original_lines = stats.total_lines;
        let compressed_lines = stats.output_lines; // Use tracked output lines (not collected_outputs.len())
        let compression_ratio = if original_lines > 0 {
            100.0 * original_lines.saturating_sub(compressed_lines) as f64 / original_lines as f64
        } else {
            0.0
        };

        match config.output_format.as_str() {
            "markdown" => {
                use std::io::Write;
                let stdout = io::stdout();
                let mut handle = stdout.lock();

                let write_line = |handle: &mut io::StdoutLock, s: String| -> Result<()> {
                    match writeln!(handle, "{s}") {
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                            std::process::exit(0);
                        }
                        Err(e) => Err(e.into()),
                    }
                };

                write_line(&mut handle, "# Log Analysis".to_string())?;
                write_line(
                    &mut handle,
                    format!(
                        "*Generated by lessence v{} on {}*\n",
                        env!("CARGO_PKG_VERSION"),
                        report::timestamp().format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                )?;
                write_line(&mut handle, "## Summary\n".to_string())?;
                write_line(
                    &mut handle,
                    format!("- **Original lines**: {original_lines}"),
                )?;
                write_line(
                    &mut handle,
                    format!("- **Compressed lines**: {compressed_lines}"),
                )?;
                write_line(
                    &mut handle,
                    format!("- **Compression ratio**: {compression_ratio:.1}%\n"),
                )?;
                write_line(&mut handle, "## Compressed Logs\n".to_string())?;

                for (i, output) in collected_outputs.iter().enumerate() {
                    // Untrusted log content always goes inside a fence whose
                    // backtick run is longer than any run in the content, so it
                    // cannot break out and inject markdown/HTML structure.
                    if output.contains('+') && output.contains("similar") {
                        write_line(&mut handle, format!("### Entry {} (Folded)\n", i + 1))?;
                        write_line(&mut handle, format!("{}\n", markdown_code_fence(output)))?;
                    } else {
                        write_line(&mut handle, format!("{}\n", markdown_code_fence(output)))?;
                    }
                }
            }
            _ => unreachable!("Should only reach here for markdown"),
        }
        if pattern_matched.get() || input_failed {
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
        if pattern_matched.get() || input_failed {
            std::process::exit(1);
        }
        return Ok(());
    }

    if config.stats_json {
        folder.print_stats_json(start_time.elapsed())?;
    } else if config.stats {
        folder.print_stats(&mut io::stderr())?;
    }

    if pattern_matched.get() || input_failed {
        std::process::exit(1);
    }

    Ok(())
}
