use anyhow::Result;
use clap::{CommandFactory, Parser};
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

use analyzer::LogAnalyzer;
use config::Config;
use folder::PatternFolder;

/// Strip ANSI escape codes from text
fn strip_ansi_codes(text: &str) -> String {
    static ANSI_REGEX: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap());
    ANSI_REGEX.replace_all(text, "").to_string()
}

const VALID_PATTERNS: &[&str] = &[
    "timestamp",
    "hash",
    "network",
    "uuid",
    "email",
    "path",
    "duration",
    "json",
    "kubernetes",
    "http-status",
    "brackets",
    "key-value",
    "process",
    "quoted-string",
    "name",
];

fn validate_min_collapse(s: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|_| format!("invalid number: '{s}'"))?;

    if value < 2 {
        return Err(format!(
            "'{value}' must be at least 2 (minimum meaningful folding group)"
        ));
    }
    Ok(value)
}

fn validate_threads(s: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|_| format!("invalid number: '{s}'"))?;

    if value < 1 {
        return Err(format!(
            "'{value}' must be at least 1 (use --threads 1 for single-threaded mode)"
        ));
    }
    Ok(value)
}

fn validate_max_lines(s: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|_| format!("invalid number: '{s}'"))?;

    if value < 1 {
        return Err(format!("'{value}' must be at least 1"));
    }
    Ok(value)
}

fn validate_pattern_names(s: &str) -> Result<String, String> {
    let pattern = s.trim().to_lowercase();

    if pattern.is_empty() {
        return Ok(pattern);
    }

    if !VALID_PATTERNS.contains(&pattern.as_str()) {
        return Err(format!(
            "unknown pattern '{}'. Valid patterns: {}",
            pattern,
            VALID_PATTERNS.join(", ")
        ));
    }

    Ok(pattern)
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Similarity percentage required to collapse (0-100)
    #[arg(long, default_value_t = 75, value_parser = clap::value_parser!(u8).range(0..=100))]
    threshold: u8,

    /// Minimum lines before folding
    #[arg(long, default_value_t = 3, value_parser = validate_min_collapse)]
    min_collapse: usize,

    /// Disable specific pattern groups (comma-separated). Valid names: timestamp, hash,
    /// network, uuid, process, email, path, duration, json, kubernetes, http-status,
    /// brackets, key-value, quoted-string, name.
    #[arg(long, value_delimiter = ',', value_parser = validate_pattern_names)]
    disable_patterns: Vec<String>,

    /// Disable statistics output (enabled by default)
    #[arg(short = 'q', long = "quiet", alias = "no-stats")]
    no_stats: bool,

    /// Preserve ANSI color codes (stripped by default)
    #[arg(long)]
    preserve_color: bool,

    /// One-line-per-pattern frequency summary (use with --top N for compact overview)
    #[arg(long)]
    summary: bool,

    /// JSON analysis report to stdout (for automation/CI)
    #[arg(long)]
    preflight: bool,

    /// Output format: text (default), markdown, json (JSONL for agent consumption)
    #[arg(long, default_value = "text")]
    format: String,

    /// Enable essence mode (timestamp removal/tokenization for temporal independence)
    #[arg(long)]
    essence: bool,

    /// Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
    #[arg(long, value_parser = validate_threads)]
    threads: Option<usize>,

    /// Enable PII sanitization (mask email addresses and sensitive data, default: disabled)
    #[arg(long)]
    sanitize_pii: bool,

    /// Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: no limit)
    #[arg(long, value_parser = config::parse_size_suffix)]
    max_line_length: Option<usize>,

    /// Maximum number of lines to process (stop after this count, default: no limit)
    #[arg(long, value_parser = validate_max_lines)]
    max_lines: Option<usize>,

    /// Emit JSON statistics to stderr (replaces human-readable stats)
    #[arg(long)]
    stats_json: bool,

    /// Show only the N most frequent patterns, sorted by count
    #[arg(long)]
    top: Option<usize>,

    /// Quick human-readable overview that fits your screen — no scrolling
    #[arg(long, alias = "human")]
    fit: bool,

    /// Exit 1 if any input line matches this regex (for CI gating)
    #[arg(long)]
    fail_on_pattern: Option<String>,

    /// Generate shell completion script and exit
    #[arg(long)]
    completions: Option<clap_complete::Shell>,

    /// Input files (reads stdin if none given, use - for explicit stdin)
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,
}

fn open_inputs(files: &[PathBuf]) -> Vec<Box<dyn BufRead>> {
    if files.is_empty() {
        return vec![Box::new(BufReader::new(io::stdin().lock()))];
    }
    let mut readers: Vec<Box<dyn BufRead>> = Vec::new();
    for path in files {
        if path.as_os_str() == "-" {
            readers.push(Box::new(BufReader::new(io::stdin().lock())));
        } else {
            match File::open(path) {
                Ok(f) => readers.push(Box::new(BufReader::new(f))),
                Err(e) => eprintln!("lessence: {}: {}", path.display(), e),
            }
        }
    }
    readers
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --completions before anything else
    if let Some(shell) = cli.completions {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "lessence", &mut io::stdout());
        return Ok(());
    }

    // Validate output format before creating config
    cli.format.parse::<output::OutputFormat>()?;

    // --fit implies --summary when no explicit mode is set
    let effective_summary = cli.summary || (cli.fit && cli.top.is_none() && !cli.preflight);

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
        // Constitutional CLI flags
        essence_mode: cli.essence,
        thread_count: cli.threads,
        // Security & ReDoS Protection flags (Constitutional Principle X)
        max_line_length: cli.max_line_length.or(Some(1024 * 1024)), // 1MB default
        max_lines: cli.max_lines,
        sanitize_pii: cli.sanitize_pii, // Wire PII sanitization flag
        top_n: cli.top,
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
    let use_top_n = config.top_n.is_some();

    // Handle preflight mode: process logs but only output JSON analysis
    if config.preflight {
        let readers = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        let mut folder = PatternFolder::new(config.clone());
        // Process all lines but don't output log content
        for (lines_processed, line) in readers
            .into_iter()
            .flat_map(std::io::BufRead::lines)
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
        if pattern_matched.get() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut folder = PatternFolder::new(config.clone());

    // Handle summary mode: use normal parallel pipeline, then output as summary
    if config.summary {
        let readers = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        for (lines_processed, line) in readers
            .into_iter()
            .flat_map(std::io::BufRead::lines)
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
        if pattern_matched.get() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let readers = open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }
    let mut stdout = io::stdout();
    let mut collected_outputs = Vec::new();
    for (lines_processed, line) in readers
        .into_iter()
        .flat_map(std::io::BufRead::lines)
        .enumerate()
    {
        let mut line = line?;

        // Security: Check line count limit
        if let Some(max_lines) = config.max_lines
            && lines_processed >= max_lines
        {
            eprintln!("Line limit of {max_lines} reached, stopping processing");
            break;
        }

        // Security: Check line length limit (Constitutional Principle X)
        if let Some(max_length) = config.max_line_length
            && line.len() > max_length
        {
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

        if let Some(output) = folder.process_line(&line)? {
            if use_top_n {
                // In top-N mode, discard incremental output — we'll use finish_top_n()
            } else if use_structured_output {
                collected_outputs.push(output);
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

    // Handle top-N mode: sort all groups by frequency and emit top N
    if let Some(n) = config.top_n {
        let (top_groups, total_groups, coverage_pct) = folder.finish_top_n(n)?;

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
            match writeln!(stdout, "[{count}x] {formatted}") {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                }
                Err(e) => return Err(e.into()),
            }
        }
        if fit_truncated > 0 {
            let _ = writeln!(
                stdout,
                "... {fit_truncated} more patterns (remove --fit for full output)"
            );
        }
        let shown = groups_to_show.len();
        eprintln!(
            "(showing top {shown} of {total_groups} patterns, covering {coverage_pct}% of input lines)"
        );

        if config.stats_json {
            folder.print_stats_json(start_time.elapsed())?;
        } else if config.stats {
            folder.print_stats(&mut io::stdout())?;
        }
        if pattern_matched.get() {
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
                Ok(_) => {}
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
            100.0 * (original_lines - compressed_lines) as f64 / original_lines as f64
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
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
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
                    if output.contains('+') && output.contains("similar") {
                        write_line(&mut handle, format!("### Entry {} (Folded)\n", i + 1))?;
                        write_line(&mut handle, "```".to_string())?;
                        write_line(&mut handle, output.clone())?;
                        write_line(&mut handle, "```\n".to_string())?;
                    } else {
                        write_line(&mut handle, format!("{output}\n"))?;
                    }
                }
            }
            _ => unreachable!("Should only reach here for markdown"),
        }
        if pattern_matched.get() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // JSON mode: emit the terminal summary record, then skip the
    // human/--stats-json paths (the summary record supersedes them).
    if matches!(config.output_format.as_str(), "json" | "jsonl") {
        folder.print_summary_json(&mut io::stdout(), start_time.elapsed())?;
        if config.stats_json {
            eprintln!(
                "lessence: --stats-json ignored in JSON mode (summary record already emitted)"
            );
        }
        if pattern_matched.get() {
            std::process::exit(1);
        }
        return Ok(());
    }

    if config.stats_json {
        folder.print_stats_json(start_time.elapsed())?;
    } else if config.stats {
        folder.print_stats(&mut io::stdout())?;
    }

    if pattern_matched.get() {
        std::process::exit(1);
    }

    Ok(())
}
