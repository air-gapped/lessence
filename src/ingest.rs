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
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;

/// One opened input: an explicit file, or stdin.
pub struct InputReader {
    /// The filename as supplied by the user, or None for stdin.
    pub source: Option<String>,
    pub reader: Box<dyn BufRead>,
}

/// Opens the given input files, falling back to stdin when none are given.
///
/// Returns the successfully opened readers plus the number of files that failed to
/// open — like cat/grep, the remaining files are still processed but the
/// process must exit non-zero.
pub fn open_inputs(files: &[PathBuf]) -> (Vec<InputReader>, usize) {
    if files.is_empty() {
        return (
            vec![InputReader {
                source: None,
                reader: Box::new(BufReader::new(io::stdin().lock())),
            }],
            0,
        );
    }
    let mut readers = Vec::new();
    let mut failed_sources = 0;
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
                    failed_sources += 1;
                }
            }
        }
    }
    (readers, failed_sources)
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
    /// Physical lines merged into the record above them by
    /// `--frame-continuations`. They were delivered, just not as records of
    /// their own, so line accounting has to add them back or the input size
    /// and compression ratio under-report.
    pub continuation_lines_absorbed: usize,
    /// Lines dropped by `--max-line-length`.
    pub overlong_lines_skipped: usize,
    /// Ingestion stopped early because `--max-lines` was reached.
    pub max_lines_reached: bool,
    /// Raw ordered-source digest, only after every reader reaches EOF.
    pub input_hash: Option<[u8; 32]>,
}

/// The configured ingestion contract. Build once per run with
/// [`Ingestor::from_config`], then drive each mode's sink via [`Ingestor::run`].
pub struct Ingestor {
    max_lines: Option<usize>,
    max_line_length: Option<usize>,
    strip_escapes: bool,
    fail_regex: Option<regex::Regex>,
    frame_continuations: bool,
    hash_input: bool,
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
            frame_continuations: config.frame_continuations,
            hash_input: false,
        })
    }

    /// Enable raw-byte identity for a run whose output can publish it.
    /// Default library ingestion and modes that cannot use a digest skip this cost.
    #[must_use]
    pub fn with_input_hash(mut self, enabled: bool) -> Self {
        self.hash_input = enabled;
        self
    }

    /// Drains the readers through the ingestion contract, delivering each
    /// surviving line to `sink` and returning the observed facts.
    pub fn run<F>(&self, readers: Vec<InputReader>, mut sink: F) -> Result<IngestReport>
    where
        F: FnMut(Event<'_>) -> Result<()>,
    {
        // These are opened readers. The CLI disables hashing after any open
        // failure, so a published CLI digest still covers all requested sources.
        let mut aggregate = self
            .hash_input
            .then(|| AggregateHash::new(readers.len()))
            .transpose()?;
        let mut report = IngestReport::default();
        let mut lines_seen = 0usize;
        // The record being assembled while `--frame-continuations` is on: its
        // text so far, and the physical line it started at. A record is only
        // handed to the sink once the next non-continuation line proves it is
        // finished, so every emit below is one line behind the read cursor.
        let mut pending: Option<(String, usize)> = None;
        'inputs: for input in readers {
            sink(Event::BeginInput {
                source: input.source.as_deref(),
            })?;
            let mut source_hash = self.hash_input.then(SourceHash::default);
            // Hash below the line decoder, so delimiters, skipped lines and
            // read-ahead are included. Only publish after complete EOF.
            let mut reader: Box<dyn BufRead + '_> = if let Some(state) = source_hash.as_mut() {
                Box::new(BufReader::new(HashingReader {
                    inner: input.reader,
                    state,
                }))
            } else {
                input.reader
            };
            for (line_index, line) in reader.by_ref().lines().enumerate() {
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

                if !self.frame_continuations {
                    sink(Event::Line {
                        text: &line,
                        line_number: line_index + 1,
                    })?;
                    continue;
                }

                // An indented line continues the record above it — a stack
                // frame, a caret row, a `Caused by:`. Joined with a space
                // rather than a newline so one record stays one line, which
                // every downstream mode assumes.
                if is_continuation(&line)
                    && let Some((text, _)) = pending.as_mut()
                {
                    text.push(' ');
                    text.push_str(line.trim_start());
                    report.continuation_lines_absorbed += 1;
                    continue;
                }

                if let Some((text, start)) = pending.replace((line, line_index + 1)) {
                    sink(Event::Line {
                        text: &text,
                        line_number: start,
                    })?;
                }
            }

            drop(reader);
            if let (Some(aggregate), Some(source)) = (aggregate.as_mut(), source_hash) {
                aggregate.push(source);
            }

            // A record still open at end of input is complete: nothing follows
            // it. Flushed inside the input loop so its line number is not
            // reported against the next file.
            if let Some((text, start)) = pending.take() {
                sink(Event::Line {
                    text: &text,
                    line_number: start,
                })?;
            }
        }
        if !report.max_lines_reached {
            report.input_hash = aggregate.map(AggregateHash::finish);
        }
        Ok(report)
    }
}

#[derive(Default)]
struct SourceHash {
    digest: Sha256,
    bytes: u64,
}
struct HashingReader<'a, R> {
    inner: R,
    state: &'a mut SourceHash,
}
impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        self.state.bytes = self
            .state
            .bytes
            .checked_add(
                u64::try_from(n).map_err(|_| io::Error::other("input byte count exceeds u64"))?,
            )
            .ok_or_else(|| io::Error::other("input byte count exceeds u64"))?;
        self.state.digest.update(&buffer[..n]);
        Ok(n)
    }
}
struct AggregateHash(Sha256);
impl AggregateHash {
    fn new(sources: usize) -> io::Result<Self> {
        let sources =
            u64::try_from(sources).map_err(|_| io::Error::other("source count exceeds u64"))?;
        let mut hash = Sha256::new();
        hash.update(b"lessence-input-hash/ordered-source-bytes-v1\0");
        hash.update(sources.to_le_bytes());
        Ok(Self(hash))
    }
    fn push(&mut self, source: SourceHash) {
        self.0.update(source.bytes.to_le_bytes());
        self.0.update(source.digest.finalize());
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// Does this line continue the record above it rather than start a new one?
///
/// Leading whitespace is the near-universal convention for a continuation:
/// Python and Java stack frames, `Caused by:` chains, YAML block scalars and
/// the caret rows under a Rust or Python error are all indented under the line
/// that introduced them. A blank line is not a continuation — it separates
/// records rather than extending one.
fn is_continuation(line: &str) -> bool {
    line.starts_with([' ', '\t']) && !line.trim().is_empty()
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

    // ---- continuation framing ----

    fn framing() -> Ingestor {
        ingestor(&Config {
            frame_continuations: true,
            ..Config::default()
        })
    }

    #[test]
    fn framing_is_off_by_default() {
        // One record per physical line remains the default: framing changes
        // what a record means, so it must be asked for.
        let ing = ingestor(&Config::default());
        let (events, report) = record(&ing, vec![reader(None, "Traceback:\n  at foo\n")]);
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                Recorded::Line("Traceback:".into(), 1),
                Recorded::Line("  at foo".into(), 2),
            ]
        );
        assert_eq!(report.continuation_lines_absorbed, 0);
    }

    #[test]
    fn framing_attaches_indented_lines_to_the_record_above() {
        let (events, report) = record(
            &framing(),
            vec![reader(None, "Traceback:\n  at foo\n\tat bar\nnext event\n")],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                // The frames join with a space: one record stays one line,
                // which every downstream mode assumes.
                Recorded::Line("Traceback: at foo at bar".into(), 1),
                Recorded::Line("next event".into(), 4),
            ]
        );
        // Both frames were read and are represented — they just are not
        // records of their own, so accounting has to add them back.
        assert_eq!(report.continuation_lines_absorbed, 2);
    }

    #[test]
    fn framed_record_reports_its_first_physical_line() {
        // The line number has to point at where the event starts, so a reader
        // can jump to it in the original file.
        let (events, _) = record(
            &framing(),
            vec![reader(
                None,
                "one
two
Traceback:\n  at foo\n  at bar\n",
            )],
        );
        assert_eq!(
            events[3],
            Recorded::Line("Traceback: at foo at bar".into(), 3)
        );
    }

    #[test]
    fn framing_flushes_a_record_left_open_at_end_of_input() {
        // Nothing follows the last frame, so the record is complete.
        let (events, _) = record(&framing(), vec![reader(None, "Traceback:\n  at foo\n")]);
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                Recorded::Line("Traceback: at foo".into(), 1),
            ]
        );
    }

    #[test]
    fn framing_does_not_carry_a_record_across_inputs() {
        // A record open at the end of one file must not swallow the first
        // line of the next, nor report its line number against it.
        let (events, _) = record(
            &framing(),
            vec![
                reader(Some("a.log"), "Traceback:\n  at foo\n"),
                reader(Some("b.log"), "  still indented\n"),
            ],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(Some("a.log".into())),
                Recorded::Line("Traceback: at foo".into(), 1),
                Recorded::Begin(Some("b.log".into())),
                // No record is open, so an indented first line is its own.
                Recorded::Line("  still indented".into(), 1),
            ]
        );
    }

    #[test]
    fn framing_treats_a_blank_line_as_a_separator_not_a_continuation() {
        // A whitespace-only line ends the record rather than extending it;
        // blank lines separate events in most formats.
        let (events, report) = record(
            &framing(),
            vec![reader(None, "Traceback:\n  at foo\n   \nnext\n")],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                Recorded::Line("Traceback: at foo".into(), 1),
                Recorded::Line("   ".into(), 3),
                Recorded::Line("next".into(), 4),
            ]
        );
        assert_eq!(report.continuation_lines_absorbed, 1);
    }

    #[test]
    fn framing_leaves_unindented_input_alone() {
        // A log with no continuations must ingest exactly as it does today.
        let text = "alpha\nbeta\ngamma\n";
        let (framed, framed_report) = record(&framing(), vec![reader(None, text)]);
        let (plain, _) = record(&ingestor(&Config::default()), vec![reader(None, text)]);
        assert_eq!(framed, plain);
        assert_eq!(framed_report.continuation_lines_absorbed, 0);
    }

    #[test]
    fn framing_still_fail_checks_every_physical_line() {
        // --fail-on-pattern is a CI gate: a match hiding inside a stack frame
        // must still trip it, so the check stays on raw physical lines.
        let ing = ingestor(&Config {
            frame_continuations: true,
            fail_pattern: Some("SecretLeak".to_string()),
            ..Config::default()
        });
        let (_, report) = record(&ing, vec![reader(None, "Traceback:\n  at SecretLeak\n")]);
        assert!(
            report.fail_pattern_matched,
            "a pattern inside a continuation line must still fail the run"
        );
    }
}

#[cfg(test)]
mod input_hash_tests {
    use super::*;
    fn hash(parts: &[&[u8]]) -> String {
        let readers = parts
            .iter()
            .map(|p| InputReader {
                source: None,
                reader: Box::new(io::Cursor::new(p.to_vec())),
            })
            .collect();
        let report = Ingestor::from_config(&Config::default())
            .unwrap()
            .with_input_hash(true)
            .run(readers, |_| Ok(()))
            .unwrap();
        format!(
            "{:x}",
            sha2::digest::Output::<Sha256>::from(report.input_hash.unwrap())
        )
    }
    #[test]
    fn framing_matches_independently_computed_vectors() {
        assert_eq!(
            hash(&[]),
            "7c239793ef2c132c9a40177131893e300ff9113ae3bd3a3e4077b3d47acc156c"
        );
        assert_eq!(
            hash(&[&[][..]]),
            "04829e7c493b8ffb6440b055bf22028567ab610a70fae68511154341cbc4df12"
        );
        assert_eq!(
            hash(&[&[97, 10][..]]),
            "136af5fb7412c9ea28f143034990456bcf3e301ff88f5307119243381f53d103"
        );
        assert_eq!(
            hash(&[&[97, 13, 10][..]]),
            "eba313f398358a48516ffd3b9f828e98f2b9b44e14b020a3388274b2862daefe"
        );
        assert_eq!(
            hash(&[&[97][..]]),
            "9f377afb9e1538ef76db4f9ff0fa88a9abed1c6950f9ef30186785db17f6e7f8"
        );
        assert_eq!(
            hash(&[&[97][..], &[98][..]]),
            "f41c7607fb22f9fd35c32f8e5122448f311a0ecfe5c77ce7e8ed15dc69d19749"
        );
        assert_eq!(
            hash(&[&[98][..], &[97][..]]),
            "b7189bc39717e41af175381143323d6f14cea94292bd5bc2418ee251ad21e765"
        );
        assert_eq!(
            hash(&[&[97, 98][..]]),
            "1cf71d09782c071b1eb8cd25b0c657e021e64279d712d3db5a2a3528b82c6b7b"
        );
        assert_eq!(
            hash(&[&[][..], &[97][..]]),
            "dc00d8167c2c43e49af26d00e367ee5408fc5f2e3c89e836c348f2bfc5451862"
        );
    }
    struct ShortReads {
        data: io::Cursor<Vec<u8>>,
        chunk: usize,
    }
    impl Read for ShortReads {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(out.len());
            self.data.read(&mut out[..n])
        }
    }
    #[test]
    fn byte_adapter_is_independent_of_read_chunking_and_counts_only_returned_bytes() {
        let bytes = b"a\r\nb\nlast";
        for chunk in 1..=bytes.len() + 2 {
            let mut state = SourceHash::default();
            let mut reader = HashingReader {
                inner: ShortReads {
                    data: io::Cursor::new(bytes.to_vec()),
                    chunk,
                },
                state: &mut state,
            };
            let mut out = [0xa5; 32];
            while reader.read(&mut out).unwrap() != 0 {}
            assert_eq!(state.bytes, bytes.len() as u64);
            assert_eq!(state.digest.finalize(), Sha256::digest(bytes));
        }
    }
    #[test]
    fn invalid_utf8_and_read_errors_do_not_produce_a_report() {
        struct ErrorAfterLine(bool);
        impl Read for ErrorAfterLine {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("test read failure"));
                }
                self.0 = true;
                out[..2].copy_from_slice(b"a\n");
                Ok(2)
            }
        }
        let ing = Ingestor::from_config(&Config::default())
            .unwrap()
            .with_input_hash(true);
        for reader in [
            Box::new(io::Cursor::new(vec![0xffu8])) as Box<dyn BufRead>,
            Box::new(BufReader::new(ErrorAfterLine(false))),
        ] {
            assert!(
                ing.run(
                    vec![InputReader {
                        source: None,
                        reader
                    }],
                    |_| Ok(())
                )
                .is_err()
            );
        }
    }
    #[test]
    fn limit_and_eof_control_publication_even_after_read_ahead() {
        let ing = Ingestor::from_config(&Config {
            max_lines: Some(1),
            ..Config::default()
        })
        .unwrap()
        .with_input_hash(true);
        for (bytes, truncated) in [(b"a\n".as_slice(), false), (b"a\nb\n".as_slice(), true)] {
            let report = ing
                .run(
                    vec![InputReader {
                        source: None,
                        reader: Box::new(io::Cursor::new(bytes.to_vec())),
                    }],
                    |_| Ok(()),
                )
                .unwrap();
            assert_eq!(report.max_lines_reached, truncated);
            assert_eq!(report.input_hash.is_none(), truncated);
        }
        let report = Ingestor::from_config(&Config::default())
            .unwrap()
            .run(
                vec![InputReader {
                    source: None,
                    reader: Box::new(io::Cursor::new(b"a\n")),
                }],
                |_| Ok(()),
            )
            .unwrap();
        assert!(
            report.input_hash.is_none(),
            "default library ingestion must not hash"
        );
    }
}
