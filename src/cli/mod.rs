//! CLI argument definitions — single source of truth for flags and
//! validators. The pattern-name list derives from
//! [`crate::config::PATTERN_REGISTRY`]. The doc-contract tests
//! (`tests/doc_contract.rs`) derive the README's generated sections from
//! [`command()`], so any flag change here is enforced against the shipped
//! docs.

use clap::{CommandFactory, Parser};
use std::path::PathBuf;

use crate::config::PATTERN_REGISTRY;

/// Valid names for `--disable-patterns`, derived at compile time from
/// [`PATTERN_REGISTRY`] — the single source of truth for the user-facing
/// pattern groups and the detector gates they control.
const VALID_PATTERNS_ARRAY: [&str; PATTERN_REGISTRY.len()] = {
    let mut names = [""; PATTERN_REGISTRY.len()];
    let mut i = 0;
    while i < names.len() {
        names[i] = PATTERN_REGISTRY[i].name;
        i += 1;
    }
    names
};
pub const VALID_PATTERNS: &[&str] = &VALID_PATTERNS_ARRAY;

fn disable_patterns_help() -> String {
    format!(
        "Disable specific pattern groups (comma-separated). Valid names: {}",
        VALID_PATTERNS.join(", ")
    )
}

fn validate_min_collapse(s: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|_| format!("invalid number: '{s}'"))?;

    // A collapsed group emits three lines (first / summary / last), so
    // lines_saved = count - 3 only makes sense for groups of 3+. Values
    // below 3 would EXPAND a 2-line group and underflow lines_saved.
    if value < 3 {
        return Err(format!(
            "'{value}' must be at least 3 (minimum meaningful folding group)"
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

/// Validate `--format` at the CLI boundary. Called from `main` (not a clap
/// value_parser) so the error message and exit path stay exactly as they
/// were when this lived behind the `output::OutputFormat` enum. The
/// accepted aliases (`plain`, `md`, `jsonl`, any case) are part of that
/// contract, even though the mode dispatch downstream compares the raw
/// string and only reacts to `markdown`, `json`, and `jsonl`.
pub fn validate_format(s: &str) -> anyhow::Result<()> {
    match s.to_lowercase().as_str() {
        "text" | "plain" | "markdown" | "md" | "json" | "jsonl" => Ok(()),
        _ => Err(anyhow::anyhow!(
            "Error: Invalid format '{s}'. Supported formats: text, markdown, json"
        )),
    }
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
pub struct Cli {
    /// Percent of tokens two lines must share to group (0-100). Lower (e.g. 75) for more folding; raise for stricter, per-message splitting
    #[arg(long, default_value_t = crate::config::DEFAULT_THRESHOLD, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub threshold: u8,

    /// Minimum lines before folding (min: 3)
    #[arg(long, default_value_t = crate::config::DEFAULT_MIN_COLLAPSE, value_parser = validate_min_collapse)]
    pub min_collapse: usize,

    /// Disable specific pattern groups (comma-separated). The valid-name
    /// list in the actual help text derives from [`PATTERN_REGISTRY`].
    #[arg(long, value_delimiter = ',', value_parser = validate_pattern_names, help = disable_patterns_help())]
    pub disable_patterns: Vec<String>,

    /// Disable statistics output (enabled by default)
    #[arg(short = 'q', long = "quiet", alias = "no-stats")]
    pub no_stats: bool,

    /// Preserve ANSI color codes (stripped by default)
    #[arg(long)]
    pub preserve_color: bool,

    /// One-line-per-pattern frequency summary (use with --top N for compact overview)
    #[arg(long)]
    pub summary: bool,

    /// JSON analysis report to stdout (for automation/CI)
    #[arg(long)]
    pub preflight: bool,

    /// Output format: text (default), markdown, json (JSONL for agent consumption)
    #[arg(long, default_value = crate::config::DEFAULT_OUTPUT_FORMAT)]
    pub format: String,

    /// Enable essence mode (timestamp removal/tokenization for temporal independence)
    #[arg(long)]
    pub essence: bool,

    /// Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
    #[arg(long, value_parser = validate_threads)]
    pub threads: Option<usize>,

    /// Enable PII sanitization (mask email addresses and sensitive data, default: disabled)
    #[arg(long)]
    pub sanitize_pii: bool,

    /// Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
    #[arg(long, value_parser = crate::config::parse_size_suffix)]
    pub max_line_length: Option<usize>,

    /// Maximum number of lines to process (stop after this count, default: no limit)
    #[arg(long, value_parser = validate_max_lines)]
    pub max_lines: Option<usize>,

    /// Emit JSON statistics to stderr (replaces human-readable stats)
    #[arg(long)]
    pub stats_json: bool,

    /// Show only the N most frequent patterns, sorted by count
    #[arg(long)]
    pub top: Option<usize>,

    /// Quick human-readable overview that fits your screen — no scrolling
    #[arg(long, alias = "human")]
    pub fit: bool,

    /// Exit 1 if any input line matches this regex (for CI gating)
    #[arg(long)]
    pub fail_on_pattern: Option<String>,

    /// Generate shell completion script and exit
    #[arg(long)]
    pub completions: Option<clap_complete::Shell>,

    /// Input files (reads stdin if none given, use - for explicit stdin)
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

/// The full clap command — single source of truth for the doc-contract tests.
pub fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_min_collapse_rejects_below_floor() {
        // 2 would make a 2-line group collapse and compute
        // lines_saved = count - 3 = 2 - 3, which underflows. The
        // validator must reject it at the CLI boundary.
        let err = validate_min_collapse("2").expect_err("2 must be rejected");
        assert!(
            err.contains("at least 3"),
            "error should state the floor of 3, got: {err}"
        );
        // The old floor and below must also be rejected.
        assert!(validate_min_collapse("1").is_err());
        assert!(validate_min_collapse("0").is_err());
    }

    #[test]
    fn validate_min_collapse_accepts_default_and_above() {
        assert_eq!(
            validate_min_collapse("3").expect("3 is the default floor"),
            3
        );
        assert_eq!(
            validate_min_collapse("10").expect("above floor accepted"),
            10
        );
    }

    // ---- validate_format ----

    #[test]
    fn format_text_and_alias() {
        assert!(validate_format("text").is_ok());
        assert!(validate_format("plain").is_ok());
    }

    #[test]
    fn format_markdown_and_alias() {
        assert!(validate_format("markdown").is_ok());
        assert!(validate_format("md").is_ok());
    }

    #[test]
    fn format_json_and_alias() {
        assert!(validate_format("json").is_ok());
        assert!(validate_format("jsonl").is_ok());
    }

    #[test]
    fn format_case_insensitive() {
        assert!(validate_format("TEXT").is_ok());
        assert!(validate_format("Json").is_ok());
    }

    #[test]
    fn format_invalid_names_supported_list() {
        let err = validate_format("xml").expect_err("xml must be rejected");
        assert_eq!(
            err.to_string(),
            "Error: Invalid format 'xml'. Supported formats: text, markdown, json"
        );
    }
}
