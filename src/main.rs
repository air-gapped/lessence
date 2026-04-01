use anyhow::Result;
use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

mod analyzer;
mod config;
mod folder;
mod normalize;
mod patterns;
mod output;
mod cli;

use config::Config;
use folder::PatternFolder;
use analyzer::LogAnalyzer;

/// Strip ANSI escape codes from text for LLM consumption
fn strip_ansi_codes(text: &str) -> String {
    // Regex pattern for ANSI escape sequences
    // \x1b matches ESC, \[ matches [, then any sequence ending with a letter
    let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    ansi_regex.replace_all(text, "").to_string()
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
    "decimal",
];

fn validate_min_collapse(s: &str) -> Result<usize, String> {
    let value = s.parse::<usize>()
        .map_err(|_| format!("invalid number: '{}'", s))?;
    
    if value < 2 {
        return Err(format!("'{}' must be at least 2 (minimum meaningful folding group)", value));
    }
    Ok(value)
}

fn validate_threads(s: &str) -> Result<usize, String> {
    let value = s.parse::<usize>()
        .map_err(|_| format!("invalid number: '{}'", s))?;
    
    if value < 1 {
        return Err(format!("'{}' must be at least 1 (use --threads 1 for single-threaded mode)", value));
    }
    Ok(value)
}

fn validate_max_lines(s: &str) -> Result<usize, String> {
    let value = s.parse::<usize>()
        .map_err(|_| format!("invalid number: '{}'", s))?;
    
    if value < 1 {
        return Err(format!("'{}' must be at least 1", value));
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

#[derive(clap::ValueEnum, Clone, Debug)]
enum AnalysisMode {
    /// Ultra-compact summary: unique patterns with counts, timestamp range only
    Summary,
    /// Enable adaptive pattern discovery for even better compression
    Adaptive,
    /// Process logs and output JSON analysis report (for LLM agents)
    Preflight,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Similarity percentage required to collapse (0-100)
    #[arg(long, default_value_t = 85, value_parser = clap::value_parser!(u8).range(0..=100))]
    threshold: u8,

    /// Minimum lines before folding
    #[arg(long, default_value_t = 3, value_parser = validate_min_collapse)]
    min_collapse: usize,


    /// Disable specific pattern groups: timestamp,hash,network,uuid,email,path,duration (comma-separated)
    #[arg(long, value_delimiter = ',', value_parser = validate_pattern_names)]
    disable_patterns: Vec<String>,

    /// Disable statistics output (enabled by default)
    #[arg(long)]
    no_stats: bool,

    /// Preserve ANSI color codes (stripped by default for LLM optimization)
    #[arg(long)]
    preserve_color: bool,

    /// Maximum tokens to output (for LLM limits, supports K/M suffixes: 5K, 1M, default: unlimited)
    #[arg(long, value_parser = parse_token_count)]
    max_tokens: Option<usize>,

    /// Analysis mode: 'summary' for ultra-compact, 'adaptive' for pattern discovery, 'preflight' for JSON report
    #[arg(long, value_enum)]
    analysis: Option<AnalysisMode>,

    /// Output format: text (default), markdown
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

    /// Input files (reads stdin if none given, use - for explicit stdin)
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,
}

fn parse_token_count(s: &str) -> Result<usize, String> {
    let s = s.trim().to_lowercase();

    if let Ok(num) = s.parse::<usize>() {
        return Ok(num);
    }

    // Handle suffixes
    if s.ends_with('k') {
        let base = s.trim_end_matches('k');
        if let Ok(num) = base.parse::<f64>() {
            return Ok((num * 1_000.0) as usize);
        }
    }

    if s.ends_with('m') {
        let base = s.trim_end_matches('m');
        if let Ok(num) = base.parse::<f64>() {
            return Ok((num * 1_000_000.0) as usize);
        }
    }

    if s.ends_with("kb") || s.ends_with("kt") {
        let base = s.trim_end_matches("kb").trim_end_matches("kt");
        if let Ok(num) = base.parse::<f64>() {
            return Ok((num * 1_000.0) as usize);
        }
    }

    if s.ends_with("mb") || s.ends_with("mt") {
        let base = s.trim_end_matches("mb").trim_end_matches("mt");
        if let Ok(num) = base.parse::<f64>() {
            return Ok((num * 1_000_000.0) as usize);
        }
    }

    Err(format!("Invalid token count format: '{}'. Use numbers or suffixes like 5K, 1M", s))
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

    // Validate output format before creating config
    cli.format.parse::<output::OutputFormat>()?;

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
        normalize_json: true, // Always enabled for modern log formats
        normalize_durations: !cli.disable_patterns.contains(&"duration".to_string()),
        normalize_kubernetes: true, // Always enabled for cloud-native logs
        output_format: cli.format,
        stats: !cli.no_stats, // Default true unless explicitly disabled
        preserve_color: cli.preserve_color,
        compact: true, // Always compact format (human-readable by default)
        max_tokens: cli.max_tokens,
        preflight: matches!(cli.analysis, Some(AnalysisMode::Preflight)),
        summary: matches!(cli.analysis, Some(AnalysisMode::Summary)),
        adaptive_min_group_size: 10,
        adaptive_max_group_size: 1000,
        // Constitutional CLI flags
        essence_mode: cli.essence,
        thread_count: cli.threads,
        // Security & ReDoS Protection flags (Constitutional Principle X)
        max_line_length: cli.max_line_length.or(Some(1024 * 1024)), // 1MB default
        max_lines: cli.max_lines,
        sanitize_pii: cli.sanitize_pii,  // Wire PII sanitization flag
    };


    // For Markdown format, we need to process all logs first, then format
    let use_structured_output = matches!(config.output_format.as_str(), "markdown");

    // Handle preflight mode: process logs but only output JSON analysis
    if config.preflight {
        let readers = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        let mut folder = PatternFolder::new(config.clone());
        // Process all lines but don't output log content
        for (lines_processed, line) in readers.into_iter().flat_map(|r| r.lines()).enumerate() {
            let line = line?;

            // Security: Check line count limit
            if let Some(max_lines) = config.max_lines {
                if lines_processed >= max_lines {
                    break;
                }
            }
            
            // Security: Check line length limit
            if let Some(max_length) = config.max_line_length {
                if line.len() > max_length {
                    continue;
                }
            }
            
            folder.process_line(&line)?;
        }
        // No need to flush - we just want the stats

        // Output JSON analysis only
        let analysis = LogAnalyzer::from_folder_stats(&folder, &config)?;
        let json_output = serde_json::to_string_pretty(&analysis)?;
        println!("{}", json_output);
        return Ok(());
    }

    let mut folder = PatternFolder::new(config.clone());

    // Handle summary mode separately
    if config.summary {
        let readers = open_inputs(&cli.files);
        if readers.is_empty() {
            eprintln!("lessence: no valid input");
            std::process::exit(1);
        }
        let chained = readers.into_iter().flat_map(|r| r.lines());
        folder.process_summary_mode(chained, &mut io::stdout())?;
        return Ok(());
    }

    let readers = open_inputs(&cli.files);
    if readers.is_empty() {
        eprintln!("lessence: no valid input");
        std::process::exit(1);
    }
    let mut stdout = io::stdout();
    let mut output_tokens = 0;
    let mut collected_outputs = Vec::new();
    for (lines_processed, line) in readers.into_iter().flat_map(|r| r.lines()).enumerate() {
        let mut line = line?;

        // Security: Check line count limit
        if let Some(max_lines) = config.max_lines {
            if lines_processed >= max_lines {
                eprintln!("Line limit of {} reached, stopping processing", max_lines);
                break;
            }
        }

        // Security: Check line length limit (Constitutional Principle X)
        if let Some(max_length) = config.max_line_length {
            if line.len() > max_length {
                continue;
            }
        }

        // Strip ANSI color codes by default (unless --preserve-color)
        if !config.preserve_color {
            line = strip_ansi_codes(&line);
        }

        if let Some(output) = folder.process_line(&line)? {
            // Check token limit before outputting
            if let Some(max_tokens) = config.max_tokens {
                let tokens = folder.count_tokens(&output);
                if output_tokens + tokens > max_tokens {
                    eprintln!("Token limit of {} reached, truncating output", max_tokens);
                    break;
                }
                output_tokens += tokens;
            }

            if use_structured_output {
                collected_outputs.push(output);
            } else {
                match writeln!(stdout, "{}", output) {
                    Ok(_) => {},
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                        std::process::exit(0);
                    },
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }

    // Flush any remaining buffered lines (respecting token limits)
    for output in folder.finish()? {
        if let Some(max_tokens) = config.max_tokens {
            let tokens = folder.count_tokens(&output);
            if output_tokens + tokens > max_tokens {
                eprintln!("Token limit of {} reached during final flush", max_tokens);
                break;
            }
            output_tokens += tokens;
        }

        if use_structured_output {
            collected_outputs.push(output);
        } else {
            match writeln!(stdout, "{}", output) {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => return Err(e.into()),
            }
        }
    }

    // Handle structured output formats
    if use_structured_output {
        let stats = folder.get_stats();
        let original_lines = stats.total_lines;
        let compressed_lines = stats.output_lines;  // Use tracked output lines (not collected_outputs.len())
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
                    match writeln!(handle, "{}", s) {
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                            std::process::exit(0);
                        },
                        Err(e) => Err(e.into()),
                    }
                };
                
                write_line(&mut handle, "# Log Analysis".to_string())?;
                write_line(&mut handle, format!("*Generated by lessence v{} on {}*\n", env!("CARGO_PKG_VERSION"), chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")))?;
                write_line(&mut handle, "## Summary\n".to_string())?;
                write_line(&mut handle, format!("- **Original lines**: {}", original_lines))?;
                write_line(&mut handle, format!("- **Compressed lines**: {}", compressed_lines))?;
                write_line(&mut handle, format!("- **Compression ratio**: {:.1}%\n", compression_ratio))?;
                write_line(&mut handle, "## Compressed Logs\n".to_string())?;

                for (i, output) in collected_outputs.iter().enumerate() {
                    if output.contains("+") && output.contains("similar") {
                        write_line(&mut handle, format!("### Entry {} (Folded)\n", i + 1))?;
                        write_line(&mut handle, "```".to_string())?;
                        write_line(&mut handle, output.clone())?;
                        write_line(&mut handle, "```\n".to_string())?;
                    } else {
                        write_line(&mut handle, format!("{}\n", output))?;
                    }
                }
            },
            _ => unreachable!("Should only reach here for markdown")
        }
        return Ok(());
    }

    if config.stats {
        folder.print_stats(&mut io::stdout())?;
        if config.max_tokens.is_some() {
            println!("Output tokens: {}", output_tokens);
        }
    }

    Ok(())
}