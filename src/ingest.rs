//! Input ingestion: the single owner of the reader-to-line contract.
//!
//! Every consumer of raw log input (the fold, `--summary`, and `--preflight`
//! loops) reads through [`Ingestor::run`], which turns a set of
//! [`InputReader`]s into sanitized, located, limit-checked [`Event`]s:
//!
//! 1. `--max-lines` cutoff — one global count across all inputs; hitting it
//!    stops ingestion with a stderr notice and is reported in [`IngestReport`].
//! 2. `--max-line-length` skip — overlong lines are dropped (and counted)
//!    before any other processing; they are never checked against the fail
//!    pattern and never delivered.
//! 3. `--fail-on-pattern` — matched against the raw line, before escape
//!    stripping, so patterns can target escape bytes themselves.
//! 4. Escape stripping — terminal escape sequences and bare C0 controls are
//!    removed unless `--preserve-color` was given.
//! 5. Provenance — each delivered line carries its 1-based line number within
//!    its input, and every input announces itself (with its filename) before
//!    its first line.

use crate::config::Config;
use anyhow::Result;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

/// One opened input: an explicit file, or stdin.
pub struct InputReader {
    /// The filename as supplied by the user, or None for stdin.
    pub source: Option<String>,
    pub reader: Box<dyn BufRead>,
}

/// Opens the given input files, falling back to stdin when none are given.
///
/// Returns the successfully opened readers plus whether any file failed to
/// open — like cat/grep, the remaining files are still processed but the
/// process must exit non-zero.
pub fn open_inputs(files: &[PathBuf]) -> (Vec<InputReader>, bool) {
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

/// One step of the ingestion stream, delivered to the sink in order.
pub enum Event<'a> {
    /// The next input is about to yield lines. `source` is its filename,
    /// or None for stdin. Emitted even for inputs that turn out empty.
    BeginInput { source: Option<&'a str> },
    /// A sanitized, limit-checked line. `line_number` is 1-based within the
    /// current input and counts skipped overlong lines, so it always matches
    /// the line's position in the original file.
    Line { text: &'a str, line_number: usize },
}

/// Facts observed while ingesting, for the caller's exit code and JSON notes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngestReport {
    /// The `--fail-on-pattern` regex matched at least one raw line.
    pub fail_pattern_matched: bool,
    /// Lines dropped by `--max-line-length`.
    pub overlong_lines_skipped: usize,
    /// Ingestion stopped early because `--max-lines` was reached.
    pub max_lines_reached: bool,
}

/// The configured ingestion contract. Build once per run with
/// [`Ingestor::from_config`], then drive each mode's sink via [`Ingestor::run`].
pub struct Ingestor {
    max_lines: Option<usize>,
    max_line_length: Option<usize>,
    strip_escapes: bool,
    fail_regex: Option<regex::Regex>,
}

impl Ingestor {
    /// Compiles the fail-on-pattern regex and captures the limit and
    /// sanitization settings. The error message is user-facing; the caller
    /// decides the exit code (the CLI uses 2, matching other usage errors).
    pub fn from_config(config: &Config) -> Result<Self> {
        let fail_regex = match config.fail_pattern.as_ref() {
            Some(pat) => Some(
                regex::Regex::new(pat)
                    .map_err(|e| anyhow::anyhow!("invalid regex '{pat}': {e}"))?,
            ),
            None => None,
        };
        Ok(Self {
            max_lines: config.max_lines,
            max_line_length: config.max_line_length,
            strip_escapes: !config.preserve_color,
            fail_regex,
        })
    }

    /// Drains the readers through the ingestion contract, delivering each
    /// surviving line to `sink` and returning the observed facts.
    pub fn run<F>(&self, readers: Vec<InputReader>, mut sink: F) -> Result<IngestReport>
    where
        F: FnMut(Event<'_>) -> Result<()>,
    {
        let mut report = IngestReport::default();
        let mut lines_seen = 0usize;
        'inputs: for input in readers {
            sink(Event::BeginInput {
                source: input.source.as_deref(),
            })?;
            for (line_index, line) in input.reader.lines().enumerate() {
                let mut line = line?;

                if let Some(max_lines) = self.max_lines
                    && lines_seen >= max_lines
                {
                    eprintln!("Line limit of {max_lines} reached, stopping processing");
                    report.max_lines_reached = true;
                    break 'inputs;
                }
                lines_seen += 1;

                if let Some(max_length) = self.max_line_length
                    && line.len() > max_length
                {
                    report.overlong_lines_skipped += 1;
                    continue;
                }

                if let Some(ref re) = self.fail_regex
                    && re.is_match(&line)
                {
                    report.fail_pattern_matched = true;
                }

                if self.strip_escapes {
                    line = strip_terminal_escapes(&line);
                }

                sink(Event::Line {
                    text: &line,
                    line_number: line_index + 1,
                })?;
            }
        }
        Ok(report)
    }
}

/// Strip terminal escape sequences and neutralize bare C0 control bytes so that
/// untrusted log content cannot drive the operator's terminal when written
/// verbatim to stdout / `--summary` / `--top` / markdown.
///
/// The CSI-only predecessor (`\x1b\[[0-9;]*[a-zA-Z]`) let OSC sequences (window
/// title `\x1b]0;...\x07`, OSC 8 hyperlinks `\x1b]8;;URL\x07text\x1b]8;;\x07`),
/// DCS/APC/PM/SOS, the lone ESC, and bare C0 controls (CR `\r`, BS `\x08`)
/// through unchanged. This is the single shared sanitizer; [`Ingestor::run`]
/// applies it to every delivered line unless `--preserve-color` was given.
///
/// 8-bit C1 introducers (0x80-0x9F) cannot arrive here: input is read via
/// `BufRead::lines`, so any C1 byte would be invalid UTF-8 and never reach a
/// `String`. Only the 7-bit ESC-introduced forms plus bare C0 controls survive,
/// and all of those are matched below.
///
/// The pattern is a single ordered alternation the linear-time `regex` engine
/// handles without backtracking (no nested unbounded quantifiers). Order
/// matters: the OSC and DCS-family arms run before the generic CSI / lone-ESC
/// arm so a whole `ESC ] ... ST` / `ESC P ... ST` is consumed as one unit.
pub fn strip_terminal_escapes(text: &str) -> String {
    static ESCAPE_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(concat!(
            // OSC: ESC ] ... terminated by BEL or ST (ESC \), or unterminated to EOL.
            r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?",
            // DCS / SOS / PM / APC: ESC P|X|^|_ ... terminated by ST, or unterminated.
            r"|\x1b[P_^X][^\x1b]*(?:\x1b\\)?",
            // CSI: ESC [ params (0x30-0x3f) intermediates (0x20-0x2f) final (0x40-0x7e).
            r"|\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]",
            // Any remaining ESC sequence (two-byte like ESC c) or a lone trailing ESC.
            r"|\x1b.?",
            // Bare C0 controls that move the cursor / overwrite: CR, BS, VT, FF.
            // Tab (\x09) is intentionally preserved; \n cannot appear (lines split).
            r"|[\r\x08\x0b\x0c]",
        ))
        .unwrap()
    });
    ESCAPE_REGEX.replace_all(text, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(source: Option<&str>, text: &str) -> InputReader {
        InputReader {
            source: source.map(str::to_string),
            reader: Box::new(io::Cursor::new(text.as_bytes().to_vec())),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Recorded {
        Begin(Option<String>),
        Line(String, usize),
    }

    fn record(ingestor: &Ingestor, readers: Vec<InputReader>) -> (Vec<Recorded>, IngestReport) {
        let mut events = Vec::new();
        let report = ingestor
            .run(readers, |event| {
                events.push(match event {
                    Event::BeginInput { source } => Recorded::Begin(source.map(str::to_string)),
                    Event::Line { text, line_number } => {
                        Recorded::Line(text.to_string(), line_number)
                    }
                });
                Ok(())
            })
            .unwrap();
        (events, report)
    }

    fn ingestor(config: &Config) -> Ingestor {
        Ingestor::from_config(config).unwrap()
    }

    // ---- max-lines cutoff ----

    #[test]
    fn max_lines_cuts_across_inputs() {
        let ing = ingestor(&Config {
            max_lines: Some(3),
            ..Config::default()
        });
        let (events, report) = record(
            &ing,
            vec![
                reader(Some("a.log"), "a1\na2\n"),
                reader(Some("b.log"), "b1\nb2\n"),
            ],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(Some("a.log".into())),
                Recorded::Line("a1".into(), 1),
                Recorded::Line("a2".into(), 2),
                Recorded::Begin(Some("b.log".into())),
                Recorded::Line("b1".into(), 1),
            ]
        );
        assert!(report.max_lines_reached);
    }

    #[test]
    fn max_lines_exact_input_size_is_not_a_cutoff() {
        let ing = ingestor(&Config {
            max_lines: Some(2),
            ..Config::default()
        });
        let (events, report) = record(&ing, vec![reader(None, "one\ntwo\n")]);
        assert_eq!(events.len(), 3); // Begin + 2 lines
        assert!(!report.max_lines_reached);
    }

    #[test]
    fn lines_beyond_max_lines_are_not_fail_checked() {
        let ing = ingestor(&Config {
            max_lines: Some(1),
            fail_pattern: Some("boom".to_string()),
            ..Config::default()
        });
        let (_, report) = record(&ing, vec![reader(None, "fine\nboom\n")]);
        assert!(!report.fail_pattern_matched);
        assert!(report.max_lines_reached);
    }

    // ---- overlong skip ----

    #[test]
    fn overlong_lines_are_skipped_counted_and_keep_numbering() {
        let ing = ingestor(&Config {
            max_line_length: Some(10),
            ..Config::default()
        });
        let long = "x".repeat(11);
        let (events, report) = record(&ing, vec![reader(None, &format!("short\n{long}\nok\n"))]);
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                Recorded::Line("short".into(), 1),
                // the skipped line still occupies line number 2
                Recorded::Line("ok".into(), 3),
            ]
        );
        assert_eq!(report.overlong_lines_skipped, 1);
    }

    #[test]
    fn line_exactly_at_length_limit_is_delivered() {
        let ing = ingestor(&Config {
            max_line_length: Some(5),
            ..Config::default()
        });
        let (events, report) = record(&ing, vec![reader(None, "12345\n")]);
        assert_eq!(
            events,
            vec![Recorded::Begin(None), Recorded::Line("12345".into(), 1)]
        );
        assert_eq!(report.overlong_lines_skipped, 0);
    }

    #[test]
    fn no_length_limit_delivers_huge_lines() {
        let ing = ingestor(&Config {
            max_line_length: None,
            max_lines: None,
            ..Config::default()
        });
        let huge = "A".repeat(10 * 1024 * 1024);
        let (events, report) = record(&ing, vec![reader(None, &format!("{huge}\n"))]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1], Recorded::Line(huge, 1));
        assert_eq!(report.overlong_lines_skipped, 0);
    }

    #[test]
    fn overlong_lines_are_not_fail_checked() {
        let ing = ingestor(&Config {
            max_line_length: Some(10),
            fail_pattern: Some("boom".to_string()),
            ..Config::default()
        });
        let (_, report) = record(&ing, vec![reader(None, "boom boom boom\n")]);
        assert!(!report.fail_pattern_matched);
        assert_eq!(report.overlong_lines_skipped, 1);
    }

    // ---- fail-on-pattern ----

    #[test]
    fn fail_pattern_match_is_reported() {
        let ing = ingestor(&Config {
            fail_pattern: Some("panic".to_string()),
            ..Config::default()
        });
        let (_, report) = record(&ing, vec![reader(None, "ok\nthread panic\n")]);
        assert!(report.fail_pattern_matched);
    }

    #[test]
    fn fail_pattern_sees_the_raw_line_before_stripping() {
        // The pattern targets the escape byte itself, which stripping removes
        // from the delivered text — so a match proves the raw line was checked.
        let ing = ingestor(&Config {
            fail_pattern: Some("\x1b\\[31m".to_string()),
            preserve_color: false,
            ..Config::default()
        });
        let (events, report) = record(&ing, vec![reader(None, "\x1b[31mred alert\x1b[0m\n")]);
        assert!(report.fail_pattern_matched);
        assert_eq!(events[1], Recorded::Line("red alert".into(), 1));
    }

    #[test]
    fn invalid_fail_pattern_is_a_user_facing_error() {
        let err = Ingestor::from_config(&Config {
            fail_pattern: Some("[".to_string()),
            ..Config::default()
        })
        .err()
        .expect("invalid regex must not compile");
        assert!(err.to_string().contains("invalid regex '['"), "got: {err}");
    }

    // ---- escape stripping ----

    #[test]
    fn preserve_color_keeps_escapes_verbatim() {
        let ing = ingestor(&Config {
            preserve_color: true,
            ..Config::default()
        });
        let (events, _) = record(&ing, vec![reader(None, "\x1b[31mERROR\x1b[0m\n")]);
        assert_eq!(events[1], Recorded::Line("\x1b[31mERROR\x1b[0m".into(), 1));
    }

    #[test]
    fn default_config_strips_escapes() {
        let ing = ingestor(&Config::default());
        let (events, _) = record(&ing, vec![reader(None, "\x1b[31mERROR\x1b[0m: failed\n")]);
        assert_eq!(events[1], Recorded::Line("ERROR: failed".into(), 1));
    }

    // ---- provenance ----

    #[test]
    fn line_numbers_restart_per_input_and_sources_are_announced() {
        let ing = ingestor(&Config::default());
        let (events, _) = record(
            &ing,
            vec![
                reader(Some("a.log"), "a1\na2\n"),
                reader(None, "s1\n"),
                reader(Some("empty.log"), ""),
            ],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(Some("a.log".into())),
                Recorded::Line("a1".into(), 1),
                Recorded::Line("a2".into(), 2),
                Recorded::Begin(None),
                Recorded::Line("s1".into(), 1),
                // empty inputs still announce themselves
                Recorded::Begin(Some("empty.log".into())),
            ]
        );
    }

    // ---- strip_terminal_escapes ----

    #[test]
    fn strip_ansi_removes_codes() {
        let input = "\x1b[31mERROR\x1b[0m: something failed";
        let result = strip_terminal_escapes(input);
        assert_eq!(result, "ERROR: something failed");
    }

    #[test]
    fn strip_ansi_no_codes() {
        let input = "plain text";
        assert_eq!(strip_terminal_escapes(input), "plain text");
    }

    #[test]
    fn strip_osc8_hyperlink() {
        // OSC 8 hyperlink: ESC]8;;URL BEL  visible-text  ESC]8;; BEL
        let input = "\x1b]8;;http://evil.example/\x07click here\x1b]8;;\x07";
        // Both OSC wrappers removed; only the visible label survives.
        assert_eq!(strip_terminal_escapes(input), "click here");
    }

    #[test]
    fn strip_osc8_hyperlink_st_terminated() {
        // Same hyperlink but terminated by ST (ESC \) instead of BEL.
        let input = "\x1b]8;;http://evil.example/\x1b\\click here\x1b]8;;\x1b\\";
        assert_eq!(strip_terminal_escapes(input), "click here");
    }

    #[test]
    fn strip_osc0_title_set() {
        // OSC 0 window-title rewrite must not reach the terminal.
        let input = "\x1b]0;you have been pwned\x07log message";
        assert_eq!(strip_terminal_escapes(input), "log message");
    }

    #[test]
    fn strip_cr_and_backspace() {
        // CR + backspace overwrite attack: "SAFE" then \r\b... to repaint "EVIL".
        let input = "SAFE\rEVIL\x08\x08\x08\x08done";
        assert_eq!(strip_terminal_escapes(input), "SAFEEVILdone");
    }

    #[test]
    fn strip_lone_trailing_escape() {
        // A lone ESC at end of line is removed, not left to swallow the next line.
        assert_eq!(strip_terminal_escapes("trailing\x1b"), "trailing");
    }

    #[test]
    fn strip_preserves_tab() {
        // Tab is legitimate content and must survive.
        assert_eq!(strip_terminal_escapes("a\tb"), "a\tb");
    }

    #[test]
    fn strip_dcs_sequence() {
        // DCS: ESC P ... ST must be removed entirely.
        let input = "before\x1bPq#0;1;2evil\x1b\\after";
        assert_eq!(strip_terminal_escapes(input), "beforeafter");
    }
}
