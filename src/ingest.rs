use crate::config::Config;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Stdin,
    File(String),
}

impl Source {
    pub fn file_name(&self) -> Option<&str> {
        match self {
            Self::Stdin => None,
            Self::File(name) => Some(name),
        }
    }

    fn display_name(&self) -> &str {
        self.file_name().unwrap_or("<stdin>")
    }
}

pub struct InputReader {
    pub source: Source,
    pub reader: Box<dyn BufRead>,
}

pub struct OpenedInputs {
    pub readers: Vec<InputReader>,
    pub failed_opens: usize,
}

pub fn open_inputs(files: &[PathBuf]) -> OpenedInputs {
    if files.is_empty() {
        return OpenedInputs {
            readers: vec![InputReader {
                source: Source::Stdin,
                reader: Box::new(BufReader::new(io::stdin().lock())),
            }],
            failed_opens: 0,
        };
    }
    let mut readers = Vec::new();
    let mut failed_opens = 0;
    // Stdin can be locked once; a second lock would wait for the first
    // forever, so a repeated `-` is skipped rather than opened.
    let mut stdin_taken = false;
    for path in files {
        if path.as_os_str() == "-" {
            if stdin_taken {
                eprintln!("lessence: -: stdin was already named; reading it once");
                continue;
            }
            stdin_taken = true;
            readers.push(InputReader {
                source: Source::Stdin,
                reader: Box::new(BufReader::new(io::stdin().lock())),
            });
        } else {
            // Windows refuses to open a directory and Unix fails only on its first
            // read, so a directory is named before it is opened.
            let opened = if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
                Err(io::Error::other("Is a directory"))
            } else {
                File::open(path)
            };
            match opened {
                Ok(f) => readers.push(InputReader {
                    source: Source::File(path.to_string_lossy().into_owned()),
                    reader: Box::new(BufReader::new(f)),
                }),
                Err(e) => {
                    eprintln!("lessence: {}: {}", path.display(), e);
                    failed_opens += 1;
                }
            }
        }
    }
    OpenedInputs {
        readers,
        failed_opens,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceLineNumber(usize);

impl SourceLineNumber {
    fn of_physical_line_index(line_index: usize) -> Self {
        Self(line_index + 1)
    }

    pub fn get(self) -> usize {
        self.0
    }
}

pub enum Event<'a> {
    BeginInput {
        source: &'a Source,
    },
    Line {
        text: &'a str,
        line_number: SourceLineNumber,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngestReport {
    pub fail_pattern_matched: bool,
    pub continuation_lines_to_add_back: usize,
    pub overlong_lines_skipped: usize,
    pub max_lines_reached: bool,
    pub complete_input_hash: Option<[u8; 32]>,
}

pub struct Ingestor {
    max_lines: Option<usize>,
    max_line_length: Option<usize>,
    strip_escapes: bool,
    fail_regex: Option<regex::Regex>,
    frame_continuations: bool,
    hash_input: bool,
}

impl Ingestor {
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

    #[must_use]
    pub fn with_input_hash_if_every_input_opened(
        mut self,
        enabled: bool,
        failed_opens: usize,
    ) -> Self {
        self.hash_input = enabled && failed_opens == 0;
        self
    }

    fn max_lines_reached_at(&self, lines_seen: usize) -> Option<usize> {
        self.max_lines.filter(|&max_lines| lines_seen >= max_lines)
    }

    fn fail_pattern_matches_raw(&self, raw_line: &str) -> bool {
        self.fail_regex
            .as_ref()
            .is_some_and(|re| re.is_match(raw_line))
    }

    fn strip_unless_preserving_color(&self, line: String) -> String {
        if self.strip_escapes
            && let Cow::Owned(stripped) = strip_terminal_escapes(&line)
        {
            stripped
        } else {
            line
        }
    }

    pub fn run<F>(&self, readers: Vec<InputReader>, mut sink: F) -> Result<IngestReport>
    where
        F: FnMut(Event<'_>) -> Result<()>,
    {
        let mut aggregate = self
            .hash_input
            .then(|| AggregateHash::new(readers.len()))
            .transpose()?;
        let mut report = IngestReport::default();
        let mut lines_seen = 0usize;
        for InputReader { source, reader } in readers {
            sink(Event::BeginInput { source: &source })?;
            let mut framer = RecordFramer::default();
            let mut source_hash = self.hash_input.then(SourceHash::default);
            let mut reader = hash_below_line_decoder(reader, source_hash.as_mut());
            let lines = PhysicalLines::new(reader.by_ref(), self.max_line_length);
            for (line_index, line) in lines.enumerate() {
                let line_number = SourceLineNumber::of_physical_line_index(line_index);
                let line = line.map_err(|e| {
                    anyhow::anyhow!("{}: line {}: {e}", source.display_name(), line_number.get())
                })?;

                if let Some(max_lines) = self.max_lines_reached_at(lines_seen) {
                    eprintln!("lessence: Line limit of {max_lines} reached, stopping processing");
                    report.max_lines_reached = true;
                    break;
                }
                lines_seen += 1;

                let Physical::Text(line) = line else {
                    report.overlong_lines_skipped += 1;
                    continue;
                };

                if self.fail_pattern_matches_raw(&line) {
                    report.fail_pattern_matched = true;
                }

                let line = self.strip_unless_preserving_color(line);

                if !self.frame_continuations {
                    sink(Event::Line {
                        text: &line,
                        line_number,
                    })?;
                    continue;
                }

                match framer.push(line, line_number) {
                    Framed::Continued => report.continuation_lines_to_add_back += 1,
                    Framed::Opened {
                        finished: Some(record),
                    } => record.emit(&mut sink)?,
                    Framed::Opened { finished: None } => {}
                }
            }

            drop(reader);
            if let (Some(aggregate), Some(source)) = (aggregate.as_mut(), source_hash) {
                aggregate.push(source);
            }

            if let Some(record) = framer.finish_at_end_of_input_or_line_limit() {
                record.emit(&mut sink)?;
            }
            if report.max_lines_reached {
                break;
            }
        }
        let every_reader_reached_eof = !report.max_lines_reached;
        if every_reader_reached_eof {
            report.complete_input_hash = aggregate.map(AggregateHash::finish);
        }
        Ok(report)
    }
}

const CONTINUATION_JOINER: &str = " ";

struct Record {
    text: String,
    first_line: SourceLineNumber,
}

impl Record {
    fn emit<F>(self, sink: &mut F) -> Result<()>
    where
        F: FnMut(Event<'_>) -> Result<()>,
    {
        sink(Event::Line {
            text: &self.text,
            line_number: self.first_line,
        })
    }
}

enum Framed {
    Continued,
    Opened { finished: Option<Record> },
}

#[derive(Default)]
struct RecordFramer {
    open: Option<Record>,
}

impl RecordFramer {
    fn push(&mut self, line: String, line_number: SourceLineNumber) -> Framed {
        if is_indented_continuation(&line)
            && let Some(open) = self.open.as_mut()
        {
            open.text.push_str(CONTINUATION_JOINER);
            open.text.push_str(line.trim_start());
            return Framed::Continued;
        }
        let finished = self.open.replace(Record {
            text: line,
            first_line: line_number,
        });
        Framed::Opened { finished }
    }

    fn finish_at_end_of_input_or_line_limit(self) -> Option<Record> {
        self.open
    }
}

const CRLF_ROOM: usize = "\r\n".len();

enum Physical {
    Text(String),
    Overlong,
}

/// `BufRead::lines` with a length limit that is applied while reading: a
/// line longer than the limit is consumed without being kept, so memory is
/// bounded by the limit rather than by the longest line. Line ends, CRLF and
/// UTF-8 errors are what `lines` gives.
struct PhysicalLines<R> {
    reader: R,
    max_length: Option<usize>,
}

fn not_utf8() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "stream did not contain valid UTF-8",
    )
}

/// The bytes at the end of `bytes` that may start a UTF-8 sequence the next
/// chunk completes, or an error when `bytes` cannot be UTF-8.
fn utf8_tail(bytes: &[u8]) -> io::Result<&[u8]> {
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok(&[]),
        Err(e) if e.error_len().is_none() => Ok(&bytes[e.valid_up_to()..]),
        Err(_) => Err(not_utf8()),
    }
}

impl<R: BufRead> PhysicalLines<R> {
    fn new(reader: R, max_length: Option<usize>) -> Self {
        Self { reader, max_length }
    }

    fn read_physical(&mut self) -> io::Result<Option<Physical>> {
        let mut buf = Vec::new();
        let read = match self.max_length {
            None => self.reader.read_until(b'\n', &mut buf)?,
            Some(max_length) => {
                let keep = max_length.saturating_add(CRLF_ROOM);
                let read = (&mut self.reader)
                    .take(keep as u64)
                    .read_until(b'\n', &mut buf)?;
                if read == keep && buf.last() != Some(&b'\n') {
                    return self.drain_overlong(&buf).map(Some);
                }
                read
            }
        };
        if read == 0 {
            return Ok(None);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        let line = String::from_utf8(buf).map_err(|_| not_utf8())?;
        if self
            .max_length
            .is_some_and(|max_length| line.len() > max_length)
        {
            return Ok(Some(Physical::Overlong));
        }
        Ok(Some(Physical::Text(line)))
    }

    fn drain_overlong(&mut self, kept: &[u8]) -> io::Result<Physical> {
        let mut valid = utf8_tail(kept).map(<[u8]>::to_vec);
        loop {
            let available = match self.reader.fill_buf() {
                Ok(available) => available,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                break;
            }
            let newline = available.iter().position(|&b| b == b'\n');
            let segment = &available[..newline.unwrap_or(available.len())];
            if let Ok(pending) = &valid {
                let mut joined = pending.clone();
                joined.extend_from_slice(segment);
                valid = utf8_tail(&joined).map(<[u8]>::to_vec);
            }
            let used = newline.map_or(available.len(), |i| i + 1);
            self.reader.consume(used);
            if newline.is_some() {
                break;
            }
        }
        match valid {
            Ok(pending) if pending.is_empty() => Ok(Physical::Overlong),
            _ => Err(not_utf8()),
        }
    }
}

impl<R: BufRead> Iterator for PhysicalLines<R> {
    type Item = io::Result<Physical>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_physical().transpose()
    }
}

fn hash_below_line_decoder<'a>(
    reader: Box<dyn BufRead>,
    state: Option<&'a mut SourceHash>,
) -> Box<dyn BufRead + 'a> {
    match state {
        Some(state) => Box::new(BufReader::new(HashingReader {
            inner: reader,
            state,
        })),
        None => reader,
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

fn is_indented_continuation(line: &str) -> bool {
    line.starts_with([' ', '\t']) && !line.trim().is_empty()
}

/// OSC: ESC ] ... terminated by BEL or ST (ESC \), or unterminated to EOL.
const OSC: &str = r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?";
/// DCS / SOS / PM / APC: ESC P|X|^|_ ... terminated by ST, or unterminated.
const DCS_SOS_PM_APC: &str = r"\x1b[P_^X][^\x1b]*(?:\x1b\\)?";
/// CSI: ESC [ params (0x30-0x3f) intermediates (0x20-0x2f) final (0x40-0x7e).
const CSI: &str = r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]";
/// Any remaining ESC sequence (two-byte like ESC c) or a lone trailing ESC.
const ANY_OTHER_ESC_OR_LONE_ESC: &str = r"\x1b.?";
/// Bare C0 controls that move the cursor / overwrite: CR, BS, VT, FF.
const CURSOR_MOVING_C0: &str = r"[\r\x08\x0b\x0c]";
const ESCAPE_ARMS_IN_MATCH_ORDER: [&str; 5] = [
    OSC,
    DCS_SOS_PM_APC,
    CSI,
    ANY_OTHER_ESC_OR_LONE_ESC,
    CURSOR_MOVING_C0,
];

/// 8-bit C1 introducers (0x80-0x9F) cannot arrive here: input is read via
/// `BufRead::lines`, so any C1 byte would be invalid UTF-8 and never reach a
/// `String`. Only the 7-bit ESC-introduced forms plus bare C0 controls survive,
/// and all of those are matched below.
pub fn strip_terminal_escapes(text: &str) -> Cow<'_, str> {
    static ESCAPE_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(&ESCAPE_ARMS_IN_MATCH_ORDER.join("|")).unwrap()
    });
    ESCAPE_REGEX.replace_all(text, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(source: Option<&str>, text: &str) -> InputReader {
        InputReader {
            source: source.map_or(Source::Stdin, |name| Source::File(name.to_string())),
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
                    Event::BeginInput { source } => {
                        Recorded::Begin(source.file_name().map(str::to_string))
                    }
                    Event::Line { text, line_number } => {
                        Recorded::Line(text.to_string(), line_number.get())
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

    fn physical(bytes: &[u8], max_length: Option<usize>) -> Vec<Result<Option<String>, String>> {
        PhysicalLines::new(io::BufReader::with_capacity(4, bytes), max_length)
            .map(|line| match line {
                Ok(Physical::Text(text)) => Ok(Some(text)),
                Ok(Physical::Overlong) => Ok(None),
                Err(e) => Err(e.to_string()),
            })
            .collect()
    }

    #[test]
    fn an_overlong_line_is_read_past_without_keeping_it_and_reads_like_lines() {
        let input = b"abc\r\nabcd\r\nabcdefghij\nok\nlast-no-newline";
        let lines_of = |bytes: &[u8]| {
            bytes
                .lines()
                .map(|l| {
                    l.map(|t| if t.len() > 3 { None } else { Some(t) })
                        .map_err(|e| e.to_string())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(physical(input, Some(3)), lines_of(input));
        assert_eq!(
            physical(input, Some(3)),
            vec![
                Ok(Some("abc".to_string())),
                Ok(None),
                Ok(None),
                Ok(Some("ok".to_string())),
                Ok(None),
            ]
        );
        assert_eq!(physical(input, None).len(), 5);

        let tail_not_utf8 = b"abcdefgh\xff\nok\n";
        assert_eq!(physical(tail_not_utf8, Some(3)), lines_of(tail_not_utf8));
        let split_char = "abcdef\u{e9}\u{e9}\nok\n".as_bytes();
        assert_eq!(physical(split_char, Some(3)), lines_of(split_char));
        let cut_char = b"abcdef\xc3\n";
        assert_eq!(physical(cut_char, Some(3)), lines_of(cut_char));
    }

    #[test]
    fn a_record_still_open_at_the_line_limit_is_emitted_with_the_lines_read() {
        let ing = ingestor(&Config {
            max_lines: Some(3),
            frame_continuations: true,
            ..Config::default()
        });
        let (events, report) = record(
            &ing,
            vec![
                reader(Some("a.log"), "start\nboom\n  at one\n  at two\nafter\n"),
                reader(Some("b.log"), "never read\n"),
            ],
        );
        assert_eq!(
            events,
            vec![
                Recorded::Begin(Some("a.log".into())),
                Recorded::Line("start".into(), 1),
                Recorded::Line("boom at one".into(), 2),
            ],
            "the three lines read are all shown, and nothing past the limit"
        );
        assert!(report.max_lines_reached);
    }

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
        assert_eq!(events.len(), 3, "BeginInput + 2 lines");
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
                Recorded::Line("ok".into(), 3),
            ],
            "the skipped line still occupies line number 2"
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
        let ing = ingestor(&Config {
            fail_pattern: Some("\x1b\\[31m".to_string()),
            preserve_color: false,
            ..Config::default()
        });
        let (events, report) = record(&ing, vec![reader(None, "\x1b[31mred alert\x1b[0m\n")]);
        assert!(
            report.fail_pattern_matched,
            "the pattern targets the escape byte that stripping removes, so a match proves the raw line was checked"
        );
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
                Recorded::Begin(Some("empty.log".into())),
            ],
            "empty inputs still announce themselves"
        );
    }

    #[test]
    fn strip_ansi_removes_codes() {
        let input = "\x1b[31mERROR\x1b[0m: something failed";
        let result = strip_terminal_escapes(input);
        assert_eq!(result, "ERROR: something failed");
    }

    #[test]
    fn a_line_with_nothing_to_strip_is_borrowed_not_copied() {
        assert!(matches!(
            strip_terminal_escapes("plain text"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(matches!(
            strip_terminal_escapes("\x1b[31mred\x1b[0m"),
            std::borrow::Cow::Owned(_)
        ));
    }

    #[test]
    fn strip_ansi_no_codes() {
        let input = "plain text";
        assert_eq!(strip_terminal_escapes(input), "plain text");
    }

    #[test]
    fn strip_osc8_hyperlink_keeps_only_the_visible_label() {
        let input = "\x1b]8;;http://evil.example/\x07click here\x1b]8;;\x07";
        assert_eq!(
            strip_terminal_escapes(input),
            "click here",
            "the OSC arm precedes the lone-ESC arm, so each whole hyperlink wrapper is consumed"
        );
    }

    #[test]
    fn strip_osc8_hyperlink_st_terminated() {
        let input = "\x1b]8;;http://evil.example/\x1b\\click here\x1b]8;;\x1b\\";
        assert_eq!(strip_terminal_escapes(input), "click here");
    }

    #[test]
    fn strip_osc0_window_title_never_reaches_the_terminal() {
        let input = "\x1b]0;you have been pwned\x07log message";
        assert_eq!(strip_terminal_escapes(input), "log message");
    }

    #[test]
    fn strip_cr_and_backspace_cannot_repaint_text() {
        let input = "SAFE\rEVIL\x08\x08\x08\x08done";
        assert_eq!(strip_terminal_escapes(input), "SAFEEVILdone");
    }

    #[test]
    fn strip_lone_trailing_escape() {
        assert_eq!(
            strip_terminal_escapes("trailing\x1b"),
            "trailing",
            "a lone ESC is removed, not left to swallow the next line"
        );
    }

    #[test]
    fn strip_preserves_tab() {
        assert_eq!(
            strip_terminal_escapes("a\tb"),
            "a\tb",
            "tab is legitimate content, outside CURSOR_MOVING_C0"
        );
    }

    #[test]
    fn strip_dcs_sequence_removes_it_entirely() {
        let input = "before\x1bPq#0;1;2evil\x1b\\after";
        assert_eq!(strip_terminal_escapes(input), "beforeafter");
    }

    fn framing() -> Ingestor {
        ingestor(&Config {
            frame_continuations: true,
            ..Config::default()
        })
    }

    #[test]
    fn framing_is_off_by_default() {
        let ing = ingestor(&Config::default());
        let (events, report) = record(&ing, vec![reader(None, "Traceback:\n  at foo\n")]);
        assert_eq!(
            events,
            vec![
                Recorded::Begin(None),
                Recorded::Line("Traceback:".into(), 1),
                Recorded::Line("  at foo".into(), 2),
            ],
            "framing changes what a record means, so it must be asked for"
        );
        assert_eq!(report.continuation_lines_to_add_back, 0);
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
                Recorded::Line("Traceback: at foo at bar".into(), 1),
                Recorded::Line("next event".into(), 4),
            ],
            "frames join with CONTINUATION_JOINER: one record stays one line"
        );
        assert_eq!(
            report.continuation_lines_to_add_back, 2,
            "absorbed frames are counted so line accounting can add them back"
        );
    }

    #[test]
    fn framed_record_reports_its_first_physical_line() {
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
            Recorded::Line("Traceback: at foo at bar".into(), 3),
            "a reader must be able to jump to the event's start in the original file"
        );
    }

    #[test]
    fn framing_flushes_a_record_left_open_at_end_of_input() {
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
                Recorded::Line("  still indented".into(), 1),
            ],
            "no record is open at the start of a file, so an indented first line is its own record"
        );
    }

    #[test]
    fn framing_treats_a_blank_line_as_a_separator_not_a_continuation() {
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
        assert_eq!(report.continuation_lines_to_add_back, 1);
    }

    #[test]
    fn framing_leaves_unindented_input_alone() {
        let text = "alpha\nbeta\ngamma\n";
        let (framed, framed_report) = record(&framing(), vec![reader(None, text)]);
        let (plain, _) = record(&ingestor(&Config::default()), vec![reader(None, text)]);
        assert_eq!(framed, plain);
        assert_eq!(framed_report.continuation_lines_to_add_back, 0);
    }

    #[test]
    fn framing_still_fail_checks_every_physical_line() {
        let ing = ingestor(&Config {
            frame_continuations: true,
            fail_pattern: Some("SecretLeak".to_string()),
            ..Config::default()
        });
        let (_, report) = record(&ing, vec![reader(None, "Traceback:\n  at SecretLeak\n")]);
        assert!(
            report.fail_pattern_matched,
            "--fail-on-pattern is a CI gate: a pattern inside a continuation line must still fail the run"
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
                source: Source::Stdin,
                reader: Box::new(io::Cursor::new(p.to_vec())),
            })
            .collect();
        let report = Ingestor::from_config(&Config::default())
            .unwrap()
            .with_input_hash_if_every_input_opened(true, 0)
            .run(readers, |_| Ok(()))
            .unwrap();
        crate::run_metadata::lower_hex(&report.complete_input_hash.unwrap())
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
            .with_input_hash_if_every_input_opened(true, 0);
        for reader in [
            Box::new(io::Cursor::new(vec![0xffu8])) as Box<dyn BufRead>,
            Box::new(BufReader::new(ErrorAfterLine(false))),
        ] {
            assert!(
                ing.run(
                    vec![InputReader {
                        source: Source::Stdin,
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
        .with_input_hash_if_every_input_opened(true, 0);
        for (bytes, truncated) in [(b"a\n".as_slice(), false), (b"a\nb\n".as_slice(), true)] {
            let report = ing
                .run(
                    vec![InputReader {
                        source: Source::Stdin,
                        reader: Box::new(io::Cursor::new(bytes.to_vec())),
                    }],
                    |_| Ok(()),
                )
                .unwrap();
            assert_eq!(report.max_lines_reached, truncated);
            assert_eq!(report.complete_input_hash.is_none(), truncated);
        }
        let report = Ingestor::from_config(&Config::default())
            .unwrap()
            .run(
                vec![InputReader {
                    source: Source::Stdin,
                    reader: Box::new(io::Cursor::new(b"a\n")),
                }],
                |_| Ok(()),
            )
            .unwrap();
        assert!(
            report.complete_input_hash.is_none(),
            "default library ingestion must not hash"
        );
    }
    #[test]
    fn a_failed_open_withholds_the_input_hash() {
        let report = Ingestor::from_config(&Config::default())
            .unwrap()
            .with_input_hash_if_every_input_opened(true, 1)
            .run(
                vec![InputReader {
                    source: Source::Stdin,
                    reader: Box::new(io::Cursor::new(b"a\n")),
                }],
                |_| Ok(()),
            )
            .unwrap();
        assert!(
            report.complete_input_hash.is_none(),
            "a published digest must cover every requested source"
        );
    }
}
