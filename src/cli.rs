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

fn validate_count(s: &str, minimum: usize, hint: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|_| format!("invalid number: '{s}'"))?;
    if value < minimum {
        return Err(format!("'{value}' must be at least {minimum}{hint}"));
    }
    Ok(value)
}

fn validate_min_collapse(s: &str) -> Result<usize, String> {
    // A collapsed group emits first / summary / last: fewer than three
    // input lines would expand the log and underflow lines_saved.
    validate_count(s, 3, " (minimum meaningful folding group)")
}

fn validate_threads(s: &str) -> Result<usize, String> {
    validate_count(s, 1, " (use --threads 1 for single-threaded mode)")
}

fn validate_max_lines(s: &str) -> Result<usize, String> {
    validate_count(s, 1, "")
}

/// Validate `--format` at the CLI boundary and return the canonical
/// spelling the mode dispatch compares against: `text`, `markdown`,
/// `json`, or `jsonl`. Accepted aliases (`plain`, `md`, any case)
/// normalize here so `--format md` and `--format JSON` behave exactly
/// like their canonical forms. Called from `main` (not a clap
/// value_parser) so the error message and exit path stay exactly as they
/// were when this lived behind the `output::OutputFormat` enum.
pub fn validate_format(s: &str) -> anyhow::Result<String> {
    match s.to_lowercase().as_str() {
        "text" | "plain" => Ok("text".to_string()),
        "markdown" | "md" => Ok("markdown".to_string()),
        canonical @ ("json" | "jsonl") => Ok(canonical.to_string()),
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

/// Shown by `--version`: semver plus the build identity embedded by `build.rs`.
///
/// The commit and target triple are part of the version because two binaries
/// with the same semver can differ — any commit between releases changes
/// behaviour without bumping Cargo.toml, and the musl build allocates
/// differently from the glibc one.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("LESSENCE_BUILD_ID"),
    ", ",
    env!("LESSENCE_TARGET"),
    ")"
);

/// The first thing `--help` says. Written for the agent reading it, the way
/// herdr's help is: an agent that already holds the skill must not fetch it
/// again, and the machine-readable surface is named before the option list.
pub const AGENT_HELP: &str = "\
Are you an AI agent? Use these ONLY IF your task specifically asks you to.
  SKIP if a lessence skill is already in your context. Otherwise run: lessence --skill
  Flag reference for agents:   lessence --skill flags
  Machine-readable output:     --format json (or --json); --explain says why lines fold or split
  Orientation before folding:  --preflight
  The default run saves the complete folded JSON report to a file and prints a bounded
  overview with that path; --no-report for `tail -f` or any source without an EOF
Humans: lessence --help-human";

/// `--help-human`: the short help for a person at a terminal. The full
/// `--help` is written for agents and is the authoritative flag list.
pub const HELP_HUMAN: &str = "\
lessence folds a repetitive log into its distinct events with counts, and keeps every unique line.

  lessence app.log                   fold a file; the overview of the saved report goes to stdout,
                                     the briefing of the log to stdout with it (stderr with --no-report)
  kubectl logs pod-x | lessence      fold anything on stdin
  lessence --fit app.log             one-screen overview, no scrolling
  lessence -q app.log                fold without the briefing

A run saves its full report to a file and prints a short overview naming that path; the
report directory grows until you delete it, and `--no-report` turns the whole thing off.

Nothing is dropped silently: the report holds every group, and everything the overview
leaves off the screen is declared in its own output.

README and examples:  https://github.com/air-gapped/lessence
Full reference:       lessence --help   (written for coding agents; its option list is complete
                      and authoritative for this build)
";

#[derive(Parser)]
#[command(author, version = VERSION, about, long_about = None, before_help = AGENT_HELP)]
pub struct Cli {
    // ---- Agent: the surface an agent reaches for first ----
    /// Print the bundled agent skill and exit: `skill` (SKILL.md, the default)
    /// or `flags` (the complete flag reference). Install with
    /// `lessence --skill > ~/.claude/skills/lessence/SKILL.md` and
    /// `lessence --skill flags > ~/.claude/skills/lessence/references/flags.md`
    #[arg(long, value_name = "TOPIC", num_args = 0..=1, default_missing_value = "skill", help_heading = "Agent")]
    pub skill: Option<String>,

    /// Output format: text (default), markdown, json (JSONL for agent consumption)
    #[arg(long, default_value = crate::config::DEFAULT_OUTPUT_FORMAT, help_heading = "Agent")]
    pub format: String,

    /// Same as --format json
    #[arg(long, conflicts_with = "format", help_heading = "Agent")]
    pub json: bool,

    /// JSON analysis report to stdout (for automation/CI)
    #[arg(long, help_heading = "Agent")]
    pub preflight: bool,

    /// Dev mode: annotate each JSON group record with the existing group it
    /// scored highest against before founding its own, the score, and the
    /// first token that differed. Implies --format json.
    #[arg(long, help_heading = "Agent")]
    pub explain: bool,

    /// Emit JSON statistics to stderr (replaces human-readable stats)
    #[arg(long, help_heading = "Agent")]
    pub stats_json: bool,

    // ---- Fold: how lines become groups ----
    /// Percent of tokens two lines must share to group (0-100). Lower (e.g. 75) for more folding; raise for stricter, per-message splitting
    #[arg(long, default_value_t = crate::config::DEFAULT_THRESHOLD, value_parser = clap::value_parser!(u8).range(0..=100), help_heading = "Fold")]
    pub threshold: u8,

    /// Minimum lines before folding (min: 3)
    #[arg(long, default_value_t = crate::config::DEFAULT_MIN_COLLAPSE, value_parser = validate_min_collapse, help_heading = "Fold")]
    pub min_collapse: usize,

    /// Disable specific pattern groups (comma-separated). The valid-name
    /// list in the actual help text derives from [`PATTERN_REGISTRY`].
    #[arg(long, value_delimiter = ',', value_parser = validate_pattern_names, help = disable_patterns_help(), help_heading = "Fold")]
    pub disable_patterns: Vec<String>,

    /// Attach indented continuation lines to the record above them, so a stack
    /// trace folds as one event instead of one group per frame
    #[arg(long, help_heading = "Fold")]
    pub frame_continuations: bool,

    /// Enable essence mode (timestamp removal/tokenization for temporal independence)
    #[arg(long, help_heading = "Fold")]
    pub essence: bool,

    // ---- Output: what is shown ----
    /// Disable statistics output (enabled by default)
    #[arg(
        short = 'q',
        long = "quiet",
        alias = "no-stats",
        help_heading = "Output"
    )]
    pub no_stats: bool,

    /// One-line-per-pattern frequency summary (use with --top N for compact overview)
    #[arg(long, help_heading = "Output")]
    pub summary: bool,

    /// Show only the N most frequent patterns, sorted by count
    #[arg(long, help_heading = "Output")]
    pub top: Option<usize>,

    /// Quick human-readable overview that fits your screen — no scrolling
    #[arg(long, alias = "human", help_heading = "Output")]
    pub fit: bool,

    /// Preserve ANSI color codes (stripped by default)
    #[arg(long, help_heading = "Output")]
    pub preserve_color: bool,

    /// Where the default run saves its report (default:
    /// $LESSENCE_REPORT_DIR, else $XDG_STATE_HOME/lessence/reports, else
    /// ~/.local/state/lessence/reports). A fresh run-YYYYmmdd-HHMMSS-8hex
    /// directory per run; the directory grows until you delete it (default
    /// text run only)
    #[arg(long, value_name = "DIR", help_heading = "Output")]
    pub report_dir: Option<PathBuf>,

    /// Per-run cap on the report file (default 1G, supports K/M/G). Nothing
    /// bounds accumulated disk use across runs (default text run only)
    #[arg(long, value_name = "N", value_parser = crate::config::parse_size_suffix, help_heading = "Output")]
    pub report_max_bytes: Option<usize>,

    /// Do not save a report: stream today's folded text to stdout and the
    /// briefing to stderr. Use this for `tail -f` and any live source — a
    /// source that never reaches EOF never gets a report (default text run
    /// only)
    #[arg(long, help_heading = "Output")]
    pub no_report: bool,

    /// Groups to show in the stdout overview: N (default 40, max 10000), 0
    /// for none, or `all` for every group with no byte budget (default text
    /// run only)
    #[arg(long, value_name = "N|all", help_heading = "Output")]
    pub overview: Option<String>,

    /// Byte budget for the whole stdout overview (default 16384) (default
    /// text run only)
    #[arg(long, value_name = "B", help_heading = "Output")]
    pub overview_bytes: Option<usize>,

    // ---- Limits and safety ----
    /// Enable PII sanitization (mask email addresses and sensitive data, default: disabled)
    #[arg(long, help_heading = "Limits and safety")]
    pub sanitize_pii: bool,

    /// Mask an entity: email, credential, host or ip, optionally with an action — redact (default) or pseudonym (a keyed tag such as <HOST:1a2b3c4d5e6f7a8b>, the same for the same value within a run, so masked hosts still fold; set LESSENCE_SANITIZE_KEY to make tags comparable across runs). Repeatable or comma-separated; --sanitize-pii equals --sanitize email,credential
    #[arg(long, value_name = "ENTITY[:ACTION]", value_delimiter = ',', action = clap::ArgAction::Append, help_heading = "Limits and safety")]
    pub sanitize: Vec<String>,

    /// Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
    #[arg(long, value_parser = crate::config::parse_size_suffix, help_heading = "Limits and safety")]
    pub max_line_length: Option<usize>,

    /// Maximum number of lines to process (stop after this count, default: no limit)
    #[arg(long, value_parser = validate_max_lines, help_heading = "Limits and safety")]
    pub max_lines: Option<usize>,

    /// Exit 1 if any input line matches this regex (for CI gating)
    #[arg(long, help_heading = "Limits and safety")]
    pub fail_on_pattern: Option<String>,

    /// Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
    #[arg(long, value_parser = validate_threads, help_heading = "Limits and safety")]
    pub threads: Option<usize>,

    // ---- Developer ----
    /// Dev mode: run this other lessence binary on the same input and print
    /// only the groups that fold differently. Exit 1 if anything moved.
    #[arg(long, value_name = "LESSENCE", help_heading = "Developer")]
    pub diff: Option<std::path::PathBuf>,

    /// Generate shell completion script and exit
    #[arg(long, help_heading = "Developer")]
    pub completions: Option<clap_complete::Shell>,

    /// Short help for people and exit (this --help is written for agents)
    #[arg(long, help_heading = "Developer")]
    pub help_human: bool,

    /// Dev mode: write the input back out as a small log that folds the same
    /// way — every group's members, every unfolded line, original order.
    #[arg(long, hide = true)]
    pub distill: bool,

    /// Dev mode: member lines kept per folded group under --distill.
    #[arg(long, hide = true, default_value_t = 3, value_parser = validate_members)]
    pub members: usize,

    /// Dev mode: replace every recognised value with an invented one of the
    /// same class and shape.
    #[arg(long, hide = true)]
    pub anonymize: bool,

    /// Dev mode: extra words to invent, one per line. Implies --anonymize.
    #[arg(long, hide = true, value_name = "FILE")]
    pub anonymize_words: Option<PathBuf>,

    /// Dev mode: seed for --anonymize, for reproducible inventions.
    #[arg(long, hide = true)]
    pub seed: Option<u64>,

    /// Input files (reads stdin if none given, use - for explicit stdin)
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

/// What the default text run does about its report, settled at the CLI
/// boundary so `main` only dispatches.
pub enum ReportPlan {
    /// `--no-report`, or any mode other than the default text run: today's
    /// streamed text and today's stderr briefing.
    Off,
    On(ReportSettings),
}

pub struct ReportSettings {
    pub dir: Option<PathBuf>,
    pub max_bytes: Option<usize>,
    pub entries: crate::overview::Entries,
    pub budget: usize,
}

impl Cli {
    /// The report flags belong to the default text run and nothing else. No
    /// flag is silently ignored: every combination outside the table in the
    /// contract is a usage error naming the flags involved.
    ///
    /// `text_default` is the caller's mode decision: no `--format` other
    /// than text, and none of the alternate output or dev modes.
    pub fn report_plan(&self, text_default: bool) -> Result<ReportPlan, String> {
        use crate::overview::{DEFAULT_BYTES, DEFAULT_ENTRIES, Entries, MAX_ENTRIES};

        let named: Vec<&str> = [
            (self.report_dir.is_some(), "--report-dir"),
            (self.report_max_bytes.is_some(), "--report-max-bytes"),
            (self.overview.is_some(), "--overview"),
            (self.overview_bytes.is_some(), "--overview-bytes"),
        ]
        .into_iter()
        .filter_map(|(hit, name)| hit.then_some(name))
        .collect();

        if !text_default {
            if let Some(flag) = named.first() {
                return Err(format!(
                    "{flag} applies to the default text run, which is the only run that saves a \
                     report; for machine-readable output use --format json on its own, which \
                     writes no report and streams every group to stdout"
                ));
            }
            if self.no_report {
                return Err(
                    "--no-report applies to the default text run, the only run that saves a \
                     report; this output mode already writes none, so drop --no-report and the \
                     command works as it stands"
                        .to_string(),
                );
            }
            return Ok(ReportPlan::Off);
        }

        if self.no_report {
            if let Some(flag) = named.first() {
                return Err(format!(
                    "--no-report writes no report, so {flag} has nothing to act on; drop \
                     --no-report to keep the report and the overview, or drop {flag} to stream \
                     today's folded text"
                ));
            }
            return Ok(ReportPlan::Off);
        }

        let entries = match self.overview.as_deref() {
            None => Entries::Count(DEFAULT_ENTRIES),
            Some("all") => Entries::All,
            Some(raw) => {
                let n: usize = raw.parse().map_err(|_| {
                    format!(
                        "--overview takes a whole number 0..={MAX_ENTRIES} or 'all', not '{raw}'"
                    )
                })?;
                if n > MAX_ENTRIES {
                    return Err(format!(
                        "--overview {n} is above the maximum of {MAX_ENTRIES}"
                    ));
                }
                Entries::Count(n)
            }
        };

        if entries == Entries::All && self.overview_bytes.is_some() {
            return Err(
                "--overview all has no byte budget; drop --overview-bytes or pick --overview N"
                    .to_string(),
            );
        }

        Ok(ReportPlan::On(ReportSettings {
            dir: self.report_dir.clone(),
            max_bytes: self.report_max_bytes,
            entries,
            budget: self.overview_bytes.unwrap_or(DEFAULT_BYTES),
        }))
    }

    /// `--distill` / `--anonymize` write a log, not a report. Every
    /// output-mode flag would be silently ignored, so a run that asks for
    /// both is a usage error naming the pair.
    pub fn validate_distill(&self) -> Result<(), String> {
        let conflicts = [
            (
                self.format != crate::config::DEFAULT_OUTPUT_FORMAT,
                "--format",
            ),
            (self.json, "--json"),
            (self.summary, "--summary"),
            (self.fit, "--fit"),
            (self.top.is_some(), "--top"),
            (self.explain, "--explain"),
            (self.diff.is_some(), "--diff"),
            (self.preflight, "--preflight"),
        ];
        let Some((_, flag)) = conflicts.into_iter().find(|(hit, _)| *hit) else {
            return Ok(());
        };
        let mode = if self.distill {
            "--distill"
        } else {
            "--anonymize"
        };
        Err(format!(
            "{mode} writes a log, not a report; {flag} cannot be combined with it"
        ))
    }
}

fn validate_members(s: &str) -> Result<usize, String> {
    validate_count(s, 1, "")
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
        assert_eq!(validate_format("text").unwrap(), "text");
        assert_eq!(validate_format("plain").unwrap(), "text");
    }

    #[test]
    fn format_markdown_and_alias() {
        assert_eq!(validate_format("markdown").unwrap(), "markdown");
        assert_eq!(validate_format("md").unwrap(), "markdown");
    }

    #[test]
    fn format_json_and_alias() {
        assert_eq!(validate_format("json").unwrap(), "json");
        assert_eq!(validate_format("jsonl").unwrap(), "jsonl");
    }

    #[test]
    fn format_case_insensitive() {
        assert_eq!(validate_format("TEXT").unwrap(), "text");
        assert_eq!(validate_format("Json").unwrap(), "json");
        assert_eq!(validate_format("MARKDOWN").unwrap(), "markdown");
    }

    fn distilling() -> Cli {
        let mut cli = Cli::parse_from(["lessence", "--distill"]);
        cli.distill = true;
        cli
    }

    #[test]
    fn distill_rejects_an_output_mode_flag_naming_both() {
        let mut cli = distilling();
        cli.format = "markdown".to_string();
        let err = cli
            .validate_distill()
            .expect_err("markdown must be rejected");
        assert!(err.contains("--distill"), "{err}");
        assert!(err.contains("--format"), "{err}");
    }

    #[test]
    fn distill_alone_is_accepted() {
        assert!(distilling().validate_distill().is_ok());
    }

    #[test]
    fn validate_members_rejects_zero() {
        assert!(validate_members("0").is_err());
        assert_eq!(validate_members("1").expect("one member is legal"), 1);
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
