//! The orientation briefing: what replaces the old "Compression Report".
//!
//! `lessence app.log` used to print a per-token occurrence table plus five
//! lines of fixed prose to stderr. Neither told an agent what it actually
//! needed before reading the fold: how big the input is, what time span it
//! covers, what shape the lines are in, how bad things got, and which
//! templates dominate. [`Briefing`] is that fact set, rendered three ways —
//! the text footer (`render_text`), `--preflight` JSON, and the `briefing`
//! field of `--explain`'s summary record — from one struct so the three
//! views can never drift apart.
//!
//! Wave 2 fills in `Span::duration_seconds`; wave 3 adds distinct-value
//! cardinality. Both are represented here (the field exists, the vec is
//! typed) but neither is computed yet.

use ahash::{AHashMap, AHashSet};
use serde::Serialize;

use crate::patterns::Token;

/// Cap on distinct templates tracked for the top-templates report. Once
/// full, existing templates keep accumulating counts but a new template is
/// dropped and [`TopTemplates::truncated`] is set. Bounds the memory cost
/// of a corpus with unbounded template diversity.
const TEMPLATE_CAP: usize = 8192;

/// How many bytes of a line are examined by the `scan_level` byte-scan
/// fallback. Format is no longer scanned at all — it is read off the
/// tokens the pipeline already produced (`format_from_line`). Level is
/// mostly free too (`level_from_tokens` reads it off a token when one is
/// present); this window only bounds the cost of the minority of lines
/// that carry a level in none of the free shapes. 64, not 200: a level
/// that appears past byte 64 is vanishingly rare in practice, and every
/// byte of window is cost paid on every line that reaches the fallback.
const LEVEL_SCAN_WINDOW: usize = 64;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Briefing {
    pub source: Option<String>,
    pub lines: usize,
    pub span: Span,
    pub format: FormatSniff,
    pub levels: Levels,
    pub templates: TopTemplates,
    pub tokens: Vec<TokenClass>,
    /// Absent when `span.duration_seconds` is `None` — a histogram needs a
    /// clock to place buckets on.
    pub histogram: Option<Histogram>,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Span {
    pub first: Option<String>,
    pub last: Option<String>,
    pub duration_seconds: Option<u64>,
    /// `lines / duration_seconds`. `None` when the duration is `None` or 0.
    pub lines_per_second: Option<f64>,
}

/// A run-length time histogram, bucketed adaptively so its footprint stays
/// bounded regardless of how many distinct instants a corpus spans — see
/// `HistogramBuilder`. `buckets` runs oldest-first across `first..=last`.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Histogram {
    pub bucket_seconds: u64,
    pub buckets: Vec<u64>,
    pub busiest_index: usize,
    pub busiest_count: u64,
    pub busiest_pct: f64,
}

/// Bounded-memory collector of one epoch second per timestamped input line.
/// Starts at 1-second resolution; once the number of distinct buckets
/// exceeds 4096 it doubles the bucket width and merges the map into itself
/// (`key -> key / 2`) so the footprint never grows past that regardless of
/// how long a run's span is. Stdin can't be re-read, so this has to get the
/// resolution right in one forward pass rather than picking a bucket width
/// up front from a span it doesn't know yet.
#[derive(Debug, Default)]
pub struct HistogramBuilder {
    bucket_seconds: u64,
    buckets: AHashMap<i64, u64>,
}

const HISTOGRAM_BUCKET_CAP: usize = 4096;

impl HistogramBuilder {
    /// Record one line's epoch second.
    pub fn record(&mut self, epoch: i64) {
        if self.bucket_seconds == 0 {
            self.bucket_seconds = 1;
        }
        let key = epoch.div_euclid(self.bucket_seconds as i64);
        *self.buckets.entry(key).or_insert(0) += 1;
        if self.buckets.len() > HISTOGRAM_BUCKET_CAP {
            let old = std::mem::take(&mut self.buckets);
            self.bucket_seconds *= 2;
            for (k, v) in old {
                *self.buckets.entry(k.div_euclid(2)).or_insert(0) += v;
            }
        }
    }

    /// Aggregate the collected buckets into at most 24 display buckets
    /// spanning `first_epoch..=last_epoch`. `None` when nothing was ever
    /// recorded.
    pub fn build(&self, first_epoch: i64, last_epoch: i64) -> Option<Histogram> {
        if self.buckets.is_empty() {
            return None;
        }
        const DISPLAY_BUCKETS: i64 = 24;
        let span = (last_epoch - first_epoch).max(0);
        let display_bucket_seconds = (span / DISPLAY_BUCKETS + 1).max(self.bucket_seconds as i64);
        let num_buckets = (span / display_bucket_seconds + 1).clamp(1, DISPLAY_BUCKETS) as usize;

        let mut buckets = vec![0u64; num_buckets];
        for (&key, &count) in &self.buckets {
            let bucket_start = key * self.bucket_seconds as i64;
            let offset = (bucket_start - first_epoch).max(0);
            let idx = ((offset / display_bucket_seconds) as usize).min(num_buckets - 1);
            buckets[idx] += count;
        }

        let (busiest_index, &busiest_count) = buckets
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .unwrap_or((0, &0));
        let total: u64 = buckets.iter().sum();

        Some(Histogram {
            bucket_seconds: display_bucket_seconds as u64,
            buckets,
            busiest_index,
            busiest_count,
            busiest_pct: pct(busiest_count as usize, total as usize),
        })
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FormatSniff {
    pub json: usize,
    pub logfmt: usize,
    pub plain: usize,
    pub dominant: &'static str,
    pub mixed: bool,
}

#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Levels {
    pub fatal: usize,
    pub error: usize,
    pub warn: usize,
    pub info: usize,
    pub debug: usize,
    pub trace: usize,
    pub lines_with_level: usize,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct TopTemplates {
    pub total_groups: usize,
    pub shown: Vec<TemplateEntry>,
    pub shown_share_pct: f64,
    pub truncated: bool,
    /// Templates whose count is exactly 1 — principle 4 in
    /// CLAUDE.local.md, "rare is signal": the top-N table alone points at
    /// the noise floor, not the tail.
    pub singletons: usize,
    pub singleton_pct: f64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct TemplateEntry {
    pub count: usize,
    pub pct: f64,
    pub template: String,
    pub first_epoch: Option<i64>,
    pub last_epoch: Option<i64>,
    /// `last_epoch - first_epoch`. `None` when no member carried a
    /// parseable timestamp.
    pub span_seconds: Option<u64>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct TokenClass {
    pub class: &'static str,
    pub occurrences: usize,
    /// Distinct values observed for this class — exact below
    /// `CARDINALITY_EXACT_CAP`, HLL-estimated above it (see
    /// `distinct_exact`). Distinguishes a small facet (a worker set worth
    /// filtering on) from a per-request correlation key (grep one value
    /// and the investigation is over) — `occurrences` alone cannot.
    pub distinct: u64,
    /// `true` while `distinct` is the exact count; `false` once the class
    /// crossed `CARDINALITY_EXACT_CAP` and `distinct` is an HLL estimate.
    pub distinct_exact: bool,
}

// -------------------------------------------------------------------------
// Format classification — per-line, no allocation, no regex.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatClass {
    Json,
    Logfmt,
    Plain,
}

/// True when the line is one top-level JSON value: first non-space byte is
/// `{` or `[` and last non-space byte is the matching close. Two byte
/// lookups after trimming, no scan — the cost of the old 200-byte walk is
/// what the token-derived classifier exists to avoid, and this does not
/// reintroduce it.
///
/// This test is needed because `Token::Json` does NOT mean "this line is
/// JSON": the detector recognises *embedded* JSON blobs (`&Event{...}`, a
/// quoted `\"{...}\"` payload), and a well-formed top-level record like
/// `{"level":"info","msg":"..."}` tokenises as its fields and never
/// produces one. Without this, a 27,760-line all-JSON argocd log reported
/// `plain 100%`, which is the opposite of the one thing the sniff is for:
/// deciding whether the next command is `jq` or `awk`.
fn is_json_line(line: &str) -> bool {
    let t = line.trim();
    let b = t.as_bytes();
    matches!(
        (b.first(), b.last()),
        (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']'))
    )
}

/// Classify one raw input line's surface format. `Json` when the line is one
/// top-level JSON value or carries an embedded `Token::Json`; `Logfmt` when
/// at least two `Token::KeyValuePair`s are present (kept as tokens, not a raw
/// `=` count: a `key="a=b"` value is a `QuotedString`, not a pair, so this
/// agrees with what the fold actually recognises); otherwise `Plain`.
pub(crate) fn format_from_line(tokens: &[Token], line: &str) -> FormatClass {
    if is_json_line(line) || tokens.iter().any(|t| matches!(t, Token::Json(_))) {
        return FormatClass::Json;
    }
    let kv_pairs = tokens
        .iter()
        .filter(|t| matches!(t, Token::KeyValuePair { .. }))
        .count();
    if kv_pairs >= 2 {
        FormatClass::Logfmt
    } else {
        FormatClass::Plain
    }
}

/// Classify one raw input line's severity, preferring the free cases the
/// token pipeline already paid for over a raw byte scan:
///
/// 1. a `Token::Timestamp` starting with a klog/glog level letter
///    (`E0909`, ...) — the letter is already inside the token.
/// 2. a `Token::LogWithModule` or `Token::StructuredMessage`, which carry
///    their own `level` field.
/// 3. a `Token::BracketContext` containing a level word.
/// 4. only then, `classify_level`'s bounded byte scan of the raw line.
pub(crate) fn level_from_tokens(tokens: &[Token], line: &str) -> Option<Level> {
    for token in tokens {
        if let Token::Timestamp(s) = token
            && let Some(level) = klog_header_level(s.as_bytes())
        {
            return Some(level);
        }
    }
    for token in tokens {
        match token {
            Token::LogWithModule { level, .. } | Token::StructuredMessage { level, .. } => {
                if let Some(level) = word_to_level(level.as_bytes()) {
                    return Some(level);
                }
            }
            _ => {}
        }
    }
    for token in tokens {
        if let Token::BracketContext(parts) = token {
            for part in parts {
                if let Some(level) = word_to_level(part.as_bytes()) {
                    return Some(level);
                }
            }
        }
    }
    classify_level(line)
}

/// The four level candidates a window walk can find, each the *first*
/// match for its own shape — exactly what the shape's original standalone
/// scan would have found. Priority order (`level()`) matches the old
/// sequential checks: bracket, then `level=`, then `severity=`, then
/// `"level":`, then a standalone caps word.
#[derive(Default)]
struct LevelScan {
    bracket_level: Option<Level>,
    level_eq: Option<Level>,
    severity_eq: Option<Level>,
    level_key: Option<Level>,
    caps_level: Option<Level>,
}

impl LevelScan {
    fn found(&self) -> bool {
        self.bracket_level.is_some()
            || self.level_eq.is_some()
            || self.severity_eq.is_some()
            || self.level_key.is_some()
            || self.caps_level.is_some()
    }

    fn level(&self) -> Option<Level> {
        self.bracket_level
            .or(self.level_eq)
            .or(self.severity_eq)
            .or(self.level_key)
            .or(self.caps_level)
    }
}

/// One byte position's worth of the four level-shape checks, folded into
/// `scan`. Shared by `scan_level` and `scan_format_and_level` so the two
/// don't drift; the caller decides whether to also track logfmt pairs.
fn scan_level_at(window: &[u8], i: usize, b: u8, scan: &mut LevelScan) {
    // -- bracketed level: `[LEVEL]` --
    if scan.bracket_level.is_none()
        && b == b'['
        && let Some(close) = window[i + 1..].iter().position(|&c| c == b']')
    {
        let inner = &window[i + 1..i + 1 + close];
        scan.bracket_level = word_to_level(inner);
    }

    // -- field level: level=, severity=, "level": --
    if scan.level_eq.is_none() {
        let key = b"level=";
        if i + key.len() <= window.len()
            && window[i..i + key.len()].eq_ignore_ascii_case(key)
            && let Some(level) = word_at(&window[i + key.len()..])
        {
            scan.level_eq = Some(level);
        }
    }
    if scan.severity_eq.is_none() {
        let key = b"severity=";
        if i + key.len() <= window.len()
            && window[i..i + key.len()].eq_ignore_ascii_case(key)
            && let Some(level) = word_at(&window[i + key.len()..])
        {
            scan.severity_eq = Some(level);
        }
    }
    if scan.level_key.is_none() {
        let key = b"\"level\":";
        if i + key.len() <= window.len() && window[i..i + key.len()].eq_ignore_ascii_case(key) {
            let mut rest = &window[i + key.len()..];
            while rest.first().is_some_and(u8::is_ascii_whitespace) {
                rest = &rest[1..];
            }
            if let Some(level) = word_at(rest) {
                scan.level_key = Some(level);
            }
        }
    }

    // -- standalone ALL-CAPS level word --
    // `start_ok` (the byte before this run is whitespace or the start of
    // the window) is false for every position inside a run except its true
    // first byte, so re-checking at each uppercase byte of a rejected run
    // is redundant work, never a spurious match.
    if scan.caps_level.is_none() && b.is_ascii_uppercase() {
        let start = i;
        let mut j = i;
        let mut all_upper = true;
        while j < window.len() && window[j].is_ascii_alphabetic() {
            if !window[j].is_ascii_uppercase() {
                all_upper = false;
            }
            j += 1;
        }
        let start_ok = start == 0 || window[start - 1].is_ascii_whitespace();
        let end_ok = j == window.len() || window[j].is_ascii_whitespace();
        if all_upper && start_ok && end_ok {
            scan.caps_level = word_to_level(&window[start..j]);
        }
    }
}

/// Level only: bracket + field + caps in one loop instead of the original
/// three separate ones. Used for JSON lines, where format is already
/// decided and only the level still needs finding.
fn scan_level(window: &[u8]) -> Option<Level> {
    let mut scan = LevelScan::default();
    let mut i = 0usize;
    while i < window.len() && !scan.found() {
        scan_level_at(window, i, window[i], &mut scan);
        i += 1;
    }
    scan.level()
}

// -------------------------------------------------------------------------
// Level classification — per-line, no allocation, no regex.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Byte-scan fallback for one raw input line's severity: klog header first
/// (free, O(5)), else the bracket/field/caps scan bounded to
/// `LEVEL_SCAN_WINDOW` bytes. This is the path `level_from_tokens` falls
/// back to once none of the free token-shaped cases matched — kept as a
/// standalone, string-only function because that is what every existing
/// test here exercises directly.
pub fn classify_level(line: &str) -> Option<Level> {
    let bytes = line.as_bytes();
    let window = &bytes[..bytes.len().min(LEVEL_SCAN_WINDOW)];
    klog_header_level(window).or_else(|| scan_level(window))
}

/// klog/glog header: the line's first byte is one of E/W/I/F, immediately
/// followed by 4 digits (`E0909`, `W0920`, ...).
fn klog_header_level(window: &[u8]) -> Option<Level> {
    if window.len() < 5 {
        return None;
    }
    let c = window[0];
    if !window[1..5].iter().all(u8::is_ascii_digit) {
        return None;
    }
    match c {
        b'E' => Some(Level::Error),
        b'W' => Some(Level::Warn),
        b'I' => Some(Level::Info),
        b'F' => Some(Level::Fatal),
        _ => None,
    }
}

/// A level word starting at `rest`, tolerating one leading `"`.
fn word_at(rest: &[u8]) -> Option<Level> {
    let rest = if rest.first() == Some(&b'"') {
        &rest[1..]
    } else {
        rest
    };
    let end = rest
        .iter()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    word_to_level(&rest[..end])
}

/// Exact, case-insensitive match of one level word against its bucket.
fn word_to_level(word: &[u8]) -> Option<Level> {
    const FATAL: &[&[u8]] = &[
        b"FATAL",
        b"CRIT",
        b"CRITICAL",
        b"EMERG",
        b"EMERGENCY",
        b"PANIC",
    ];
    const ERROR: &[&[u8]] = &[b"ERROR", b"ERR"];
    const WARN: &[&[u8]] = &[b"WARN", b"WARNING"];
    const INFO: &[&[u8]] = &[b"INFO", b"NOTICE", b"INFORMATION"];
    const DEBUG: &[&[u8]] = &[b"DEBUG"];
    const TRACE: &[&[u8]] = &[b"TRACE"];

    let matches = |list: &[&[u8]]| list.iter().any(|w| word.eq_ignore_ascii_case(w));
    if matches(FATAL) {
        Some(Level::Fatal)
    } else if matches(ERROR) {
        Some(Level::Error)
    } else if matches(WARN) {
        Some(Level::Warn)
    } else if matches(INFO) {
        Some(Level::Info)
    } else if matches(DEBUG) {
        Some(Level::Debug)
    } else if matches(TRACE) {
        Some(Level::Trace)
    } else {
        None
    }
}

// -------------------------------------------------------------------------
// Distinct-value cardinality per token class (lessence-nn3).
//
// A HyperLogLog++ shape in its simplest correct form: exact below
// `CARDINALITY_EXACT_CAP` (plain HLL is inaccurate at low cardinality,
// which is exactly the facet case — reporting 12 distinct pods as 9 or 15
// is worse than reporting nothing), a dense HLL estimator above it, where
// a few percent of error changes no decision.
// -------------------------------------------------------------------------

/// Below this many distinct values, [`CardinalityEstimator`] keeps an
/// exact set; at and above it, a dense HLL estimate.
const CARDINALITY_EXACT_CAP: usize = 2048;

/// `p` for the dense HLL: `2^10 = 1024` registers.
const HLL_P: u32 = 10;
const HLL_M: usize = 1 << HLL_P;

#[derive(Debug, Clone)]
enum CardinalityState {
    Exact(AHashSet<u64>),
    Hll(Box<[u8; HLL_M]>),
}

/// Per-token-class distinct-value counter. Insert pre-hashed `u64`s (see
/// `hash_token_value`); read back with `distinct()`/`is_exact()`.
#[derive(Debug, Clone)]
pub struct CardinalityEstimator {
    state: CardinalityState,
}

impl Default for CardinalityEstimator {
    fn default() -> Self {
        Self {
            state: CardinalityState::Exact(AHashSet::new()),
        }
    }
}

impl CardinalityEstimator {
    /// Record one (already-hashed) value.
    pub fn insert(&mut self, hash: u64) {
        match &mut self.state {
            CardinalityState::Exact(set) => {
                if set.contains(&hash) {
                    return;
                }
                if set.len() < CARDINALITY_EXACT_CAP {
                    set.insert(hash);
                } else {
                    // The insert that would exceed the cap: convert once,
                    // replaying the retained exact hashes into a dense HLL.
                    let mut registers = Box::new([0u8; HLL_M]);
                    for &h in set.iter() {
                        hll_add(&mut registers, h);
                    }
                    hll_add(&mut registers, hash);
                    self.state = CardinalityState::Hll(registers);
                }
            }
            CardinalityState::Hll(registers) => hll_add(registers, hash),
        }
    }

    /// `true` while the exact set is still in use.
    pub fn is_exact(&self) -> bool {
        matches!(self.state, CardinalityState::Exact(_))
    }

    /// The distinct count: exact below the cap, an HLL estimate above it.
    pub fn distinct(&self) -> u64 {
        match &self.state {
            CardinalityState::Exact(set) => set.len() as u64,
            CardinalityState::Hll(registers) => hll_estimate(registers),
        }
    }
}

/// One HLL insert: `register[top 10 bits] = max(register, leading zeros of
/// the remaining 54 bits + 1)`.
fn hll_add(registers: &mut [u8; HLL_M], hash: u64) {
    let idx = (hash >> (64 - HLL_P)) as usize;
    let rest = hash << HLL_P;
    let rank = (rest.leading_zeros() + 1) as u8;
    if rank > registers[idx] {
        registers[idx] = rank;
    }
}

/// Standard HLL estimator with the small-range linear-counting correction.
/// Only ever read above `CARDINALITY_EXACT_CAP`, so the result is clamped
/// to at least `CARDINALITY_EXACT_CAP + 1` — the conversion to HLL only
/// ever happens once that many distinct values were already confirmed.
fn hll_estimate(registers: &[u8; HLL_M]) -> u64 {
    let m = HLL_M as f64;
    let alpha = 0.7213 / (1.0 + 1.079 / m); // alpha_m, valid for m >= 128
    let sum: f64 = registers.iter().map(|&r| 2f64.powi(-(i32::from(r)))).sum();
    let raw = alpha * m * m / sum;

    let zero_registers = registers
        .iter()
        .fold(0usize, |acc, &r| acc + usize::from(r == 0));
    let estimate = if raw <= 2.5 * m && zero_registers > 0 {
        m * (m / zero_registers as f64).ln()
    } else {
        raw
    };

    (estimate.round() as u64).max(CARDINALITY_EXACT_CAP as u64 + 1)
}

// -------------------------------------------------------------------------
// Epoch extraction — per-line, no allocation, no regex, byte position only.
// -------------------------------------------------------------------------

/// Epoch seconds for a raw timestamp string, or `None` when the shape isn't
/// one we can place on a clock. Tries, in order: a bare all-digit epoch (10
/// seconds / 13 millis / 16 micros / 19 nanos); klog/glog (`E0909
/// 13:07:09`); ISO 8601 / space-separated (`2025-09-09T13:07:09` or
/// `2025-09-09 13:07:09`); slash-date (`2025/09/09 13:07:09`); Apache CLF
/// (`09/Sep/2025:13:07:09`); syslog BSD / ANSI C asctime (`Sep  9
/// 13:07:09`, optionally with a leading weekday and/or trailing year); and
/// compact (`20250909T130709`). Anything else is `None`.
///
/// klog and syslog BSD carry no year, so this stamps them with the current
/// UTC year — a year-less log spanning more than a year is unrepresentable
/// by a single raw string and this function does not pretend otherwise. The
/// span/histogram code that consumes this handles a Dec→Jan wrap across two
/// same-year-stamped timestamps by rolling the later one forward a year.
pub(crate) fn epoch_seconds(ts: &str) -> Option<i64> {
    let trimmed = ts.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    if bytes.iter().all(u8::is_ascii_digit) {
        let n: i64 = trimmed.parse().ok()?;
        return match bytes.len() {
            10 => Some(n),
            13 => Some(n / 1_000),
            16 => Some(n / 1_000_000),
            19 => Some(n / 1_000_000_000),
            _ => None,
        };
    }

    parse_klog_epoch(bytes)
        .or_else(|| parse_iso_epoch(bytes))
        .or_else(|| parse_slash_date_epoch(bytes))
        .or_else(|| parse_clf_epoch(bytes))
        .or_else(|| parse_compact_epoch(bytes))
        .or_else(|| parse_syslog_or_asctime_epoch(trimmed))
}

/// Two ASCII digits as a number, or `None` if either byte isn't a digit.
fn d2(b: &[u8]) -> Option<u32> {
    if b.len() == 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
        Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
    } else {
        None
    }
}

/// Four ASCII digits as a number, or `None` if any byte isn't a digit.
fn d4(b: &[u8]) -> Option<i32> {
    if b.len() == 4 && b.iter().all(u8::is_ascii_digit) {
        Some(
            b.iter()
                .fold(0i32, |acc, &c| acc * 10 + i32::from(c - b'0')),
        )
    } else {
        None
    }
}

/// `Jan`..`Dec`, case-insensitive, as a 1-based month number.
fn month_abbrev(w: &[u8]) -> Option<u32> {
    const NAMES: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    if w.len() != 3 {
        return None;
    }
    NAMES
        .iter()
        .position(|n| n.eq_ignore_ascii_case(w))
        .map(|i| i as u32 + 1)
}

/// The current UTC year — used to stamp the two year-less shapes (klog,
/// syslog BSD).
/// The current UTC year, computed once per process — `epoch_seconds` can
/// run on every input line, and a syscall-backed `Utc::now()` on every
/// klog/syslog-BSD line measurably regressed the perf gate before this
/// cache. The year cannot change mid-run in any way that matters here.
fn current_utc_year() -> i32 {
    use chrono::Datelike;
    static YEAR: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *YEAR.get_or_init(|| chrono::Utc::now().year())
}

// Midnight-epoch of the most recently converted (year, month, day), so a
// run of consecutive lines sharing a calendar date (the overwhelmingly
// common case — a date changes at most a few times a run, a clock changes
// every line) pays for `NaiveDate::from_ymd_opt`'s validation once per
// date instead of once per line.
thread_local! {
    static LAST_DATE_MIDNIGHT: std::cell::Cell<Option<(i32, u32, u32, i64)>> =
        const { std::cell::Cell::new(None) };
}

fn ymd_hms_to_epoch(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    let midnight = LAST_DATE_MIDNIGHT.with(|cell| {
        if let Some((y, m, d, epoch)) = cell.get()
            && (y, m, d) == (year, month, day)
        {
            return Some(epoch);
        }
        let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
        let epoch = date.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
        cell.set(Some((year, month, day, epoch)));
        Some(epoch)
    })?;
    Some(midnight + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
}

/// klog/glog: `E0909 13:07:09.181236` — no year, current UTC year assumed.
fn parse_klog_epoch(b: &[u8]) -> Option<i64> {
    if b.len() < 14 || !matches!(b[0], b'E' | b'W' | b'I' | b'F') {
        return None;
    }
    let month = d2(&b[1..3])?;
    let day = d2(&b[3..5])?;
    if b[5] != b' ' {
        return None;
    }
    let hour = d2(&b[6..8])?;
    if b[8] != b':' {
        return None;
    }
    let min = d2(&b[9..11])?;
    if b[11] != b':' {
        return None;
    }
    let sec = d2(&b[12..14])?;
    ymd_hms_to_epoch(current_utc_year(), month, day, hour, min, sec)
}

/// ISO 8601 / space-separated: `2025-09-09T13:07:09` or `2025-09-09
/// 13:07:09`.
fn parse_iso_epoch(b: &[u8]) -> Option<i64> {
    if b.len() < 19 {
        return None;
    }
    let year = d4(&b[0..4])?;
    if b[4] != b'-' {
        return None;
    }
    let month = d2(&b[5..7])?;
    if b[7] != b'-' {
        return None;
    }
    let day = d2(&b[8..10])?;
    if b[10] != b'T' && b[10] != b' ' {
        return None;
    }
    let hour = d2(&b[11..13])?;
    if b[13] != b':' {
        return None;
    }
    let min = d2(&b[14..16])?;
    if b[16] != b':' {
        return None;
    }
    let sec = d2(&b[17..19])?;
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

/// glog/rancher slash-date: `2025/09/09 13:07:09`.
fn parse_slash_date_epoch(b: &[u8]) -> Option<i64> {
    if b.len() < 19 {
        return None;
    }
    let year = d4(&b[0..4])?;
    if b[4] != b'/' {
        return None;
    }
    let month = d2(&b[5..7])?;
    if b[7] != b'/' {
        return None;
    }
    let day = d2(&b[8..10])?;
    if b[10] != b' ' {
        return None;
    }
    let hour = d2(&b[11..13])?;
    if b[13] != b':' {
        return None;
    }
    let min = d2(&b[14..16])?;
    if b[16] != b':' {
        return None;
    }
    let sec = d2(&b[17..19])?;
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

/// Apache CLF: `09/Sep/2025:13:07:09`.
fn parse_clf_epoch(b: &[u8]) -> Option<i64> {
    if b.len() < 20 {
        return None;
    }
    let day = d2(&b[0..2])?;
    if b[2] != b'/' {
        return None;
    }
    let month = month_abbrev(&b[3..6])?;
    if b[6] != b'/' {
        return None;
    }
    let year = d4(&b[7..11])?;
    if b[11] != b':' {
        return None;
    }
    let hour = d2(&b[12..14])?;
    if b[14] != b':' {
        return None;
    }
    let min = d2(&b[15..17])?;
    if b[17] != b':' {
        return None;
    }
    let sec = d2(&b[18..20])?;
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

/// Compact: `20250909T130709`.
fn parse_compact_epoch(b: &[u8]) -> Option<i64> {
    if b.len() != 15 {
        return None;
    }
    let year = d4(&b[0..4])?;
    let month = d2(&b[4..6])?;
    let day = d2(&b[6..8])?;
    if b[8] != b'T' {
        return None;
    }
    let hour = d2(&b[9..11])?;
    let min = d2(&b[11..13])?;
    let sec = d2(&b[13..15])?;
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

/// syslog BSD (`Sep  9 13:07:09`, no year) or ANSI C asctime (`Sat Sep 9
/// 13:07:09 2025`, weekday and year both present). Word-split rather than
/// byte-position, since the day field is 1 or 2 digits and may be
/// space-padded.
fn parse_syslog_or_asctime_epoch(s: &str) -> Option<i64> {
    let mut fields = s.split_ascii_whitespace();
    let mut first = fields.next()?;
    let month = if let Some(m) = month_abbrev(first.as_bytes()) {
        m
    } else {
        // Leading weekday name — the month is the next field.
        first = fields.next()?;
        month_abbrev(first.as_bytes())?
    };
    let day: u32 = fields.next()?.parse().ok()?;
    let time = fields.next()?;
    let tb = time.as_bytes();
    if tb.len() != 8 || tb[2] != b':' || tb[5] != b':' {
        return None;
    }
    let hour = d2(&tb[0..2])?;
    let min = d2(&tb[3..5])?;
    let sec = d2(&tb[6..8])?;
    let year = match fields.next() {
        Some(y) if y.len() == 4 && y.bytes().all(|c| c.is_ascii_digit()) => y.parse().ok()?,
        _ => current_utc_year(),
    };
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

/// Roll `epoch` forward exactly one calendar year (UTC), for the case where
/// a year-less span's `last` epoch landed before its `first` because both
/// were stamped with the same assumed year but the log actually crossed
/// New Year's. `None` on the Feb-29-into-non-leap-year edge case, which the
/// caller falls back on rather than mis-date.
fn add_one_year_utc(epoch: i64) -> Option<i64> {
    use chrono::Datelike;
    let dt = chrono::DateTime::from_timestamp(epoch, 0)?;
    let naive = dt.naive_utc();
    let bumped_date = naive.date().with_year(naive.year() + 1)?;
    Some(bumped_date.and_time(naive.time()).and_utc().timestamp())
}

/// Duration in seconds between two raw timestamp strings, handling the
/// year-less New Year wrap (see `epoch_seconds`'s doc comment): if the
/// computed `last` epoch is before `first`, roll `last` forward a year and
/// use that instead. `None` when either string doesn't parse.
pub(crate) fn span_epochs(first: &str, last: &str) -> Option<(i64, i64)> {
    let first_epoch = epoch_seconds(first)?;
    let mut last_epoch = epoch_seconds(last)?;
    if last_epoch < first_epoch {
        last_epoch = add_one_year_utc(last_epoch).unwrap_or(last_epoch);
    }
    Some((first_epoch, last_epoch))
}

pub(crate) fn span_duration_seconds(first: &str, last: &str) -> Option<u64> {
    let (first_epoch, last_epoch) = span_epochs(first, last)?;
    u64::try_from(last_epoch - first_epoch).ok()
}

// -------------------------------------------------------------------------
// Template counts — accumulated across group flushes (lessence-940: a
// template can flush more than once as its group fragments across
// evictions, so this map accumulates rather than overwrites).
// -------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TemplateAcc {
    count: usize,
    first_epoch: Option<i64>,
    last_epoch: Option<i64>,
}

#[derive(Debug, Default)]
pub struct TemplateCounts {
    map: AHashMap<String, TemplateAcc>,
    truncated: bool,
}

impl TemplateCounts {
    /// Record one flushed group's template, member count, and the earliest
    /// / latest parseable epoch among its members (`None` when none of the
    /// flushed members carried one). Once the map hits `TEMPLATE_CAP`
    /// distinct templates, an existing key keeps accumulating but a new one
    /// is dropped and `truncated` is set. Repeated flushes of the same
    /// template (lessence-940: a group can fragment across evictions)
    /// widen the epoch range rather than overwrite it.
    pub fn record(
        &mut self,
        template: &str,
        count: usize,
        first_epoch: Option<i64>,
        last_epoch: Option<i64>,
    ) {
        if let Some(existing) = self.map.get_mut(template) {
            existing.count += count;
            existing.first_epoch = min_opt(existing.first_epoch, first_epoch);
            existing.last_epoch = max_opt(existing.last_epoch, last_epoch);
        } else if self.map.len() < TEMPLATE_CAP {
            self.map.insert(
                template.to_string(),
                TemplateAcc {
                    count,
                    first_epoch,
                    last_epoch,
                },
            );
        } else {
            self.truncated = true;
        }
    }

    /// Sum of every recorded member count — used by the debug-only
    /// completeness check in `PatternFolder::build_briefing` and by tests.
    pub fn total_members(&self) -> usize {
        self.map.values().map(|a| a.count).sum()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Build the top-10-by-count report. Ties break by template string
    /// ascending, so the shown set is deterministic across runs.
    pub fn build(&self, total_lines: usize) -> TopTemplates {
        let mut entries: Vec<(&String, &TemplateAcc)> = self.map.iter().collect();
        entries.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));

        let shown: Vec<TemplateEntry> = entries
            .into_iter()
            .take(10)
            .map(|(template, acc)| TemplateEntry {
                count: acc.count,
                pct: pct(acc.count, total_lines),
                template: template.clone(),
                first_epoch: acc.first_epoch,
                last_epoch: acc.last_epoch,
                span_seconds: match (acc.first_epoch, acc.last_epoch) {
                    (Some(f), Some(l)) => u64::try_from(l - f).ok(),
                    _ => None,
                },
            })
            .collect();
        let shown_sum: usize = shown.iter().map(|e| e.count).sum();

        let singletons = self.map.values().filter(|a| a.count == 1).count();

        TopTemplates {
            total_groups: self.map.len(),
            shown_share_pct: pct(shown_sum, total_lines),
            shown,
            truncated: self.truncated,
            singletons,
            singleton_pct: pct(singletons, total_lines),
        }
    }
}

fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

// -------------------------------------------------------------------------
// Text rendering — the stderr briefing footer.
// -------------------------------------------------------------------------

/// Thousands-grouped decimal: `3951` -> `"3,951"`.
fn fmt_count(n: usize) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// One decimal place, with a trailing `.0` stripped (`100.0%` -> `100%`,
/// `55.4%` stays `55.4%`).
fn fmt_pct(value: f64) -> String {
    let s = format!("{value:.1}%");
    s.strip_suffix(".0%")
        .map_or(s.clone(), |head| format!("{head}%"))
}

/// Truncate to `max_chars` characters (char-safe), appending `…` when the
/// string was actually cut.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut it = s.chars();
    let head: String = it.by_ref().take(max_chars).collect();
    if it.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

fn render_span_line(span: &Span) -> String {
    match (&span.first, &span.last) {
        (Some(first), Some(last)) => {
            let mut line = format!("span:    {first} \u{2192} {last}");
            if let Some(duration) = span.duration_seconds {
                let humanized = humanize_duration(duration);
                match span.lines_per_second {
                    Some(lps) => line.push_str(&format!("  ({humanized}, {lps:.3} lines/s)")),
                    None => line.push_str(&format!("  ({humanized})")),
                }
            }
            line
        }
        _ => "span:    (no timestamps detected)".to_string(),
    }
}

/// The largest two non-zero units of a duration (`11d 1h`, `5h 51m`,
/// `47s`). Never more than two, so a multi-year span still reads at a
/// glance rather than spelling out every unit down to the second.
fn humanize_duration(mut seconds: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)];
    let mut parts = Vec::new();
    for (name, unit_seconds) in UNITS {
        if seconds >= unit_seconds {
            parts.push(format!("{}{name}", seconds / unit_seconds));
            seconds %= unit_seconds;
        }
        if parts.len() == 2 {
            break;
        }
    }
    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

/// The `shape:` sparkline line under `span:` — one of the eight block
/// glyphs per display bucket, scaled linearly against the busiest bucket;
/// an empty bucket renders as a plain space so a gap in traffic is visible
/// as a gap, not a false floor.
fn render_shape_line(hist: &Histogram, span_first_epoch: i64, dated: bool) -> String {
    const BLOCKS: [char; 8] = [
        '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let sparkline: String = hist
        .buckets
        .iter()
        .map(|&count| {
            if count == 0 || hist.busiest_count == 0 {
                ' '
            } else {
                let scaled = (count as f64 / hist.busiest_count as f64 * BLOCKS.len() as f64)
                    .ceil()
                    .clamp(1.0, BLOCKS.len() as f64) as usize;
                BLOCKS[scaled - 1]
            }
        })
        .collect();

    let busiest_start = span_first_epoch + hist.busiest_index as i64 * hist.bucket_seconds as i64;
    let busiest_time = epoch_to_display(busiest_start, dated);
    let width = humanize_duration(hist.bucket_seconds);
    format!(
        "shape:   {sparkline}  busiest {busiest_time} +{width} holds {} ({})",
        fmt_count(hist.busiest_count as usize),
        fmt_pct(hist.busiest_pct)
    )
}

/// True when a raw timestamp string states its own year. klog (`E0909
/// 13:07:09`) and syslog BSD (`Sep  9 13:07:09`) do not, so `epoch_seconds`
/// supplies the current year to place them on a clock.
///
/// That inference is fine for measuring a span — the arithmetic is unaffected
/// — but printing the inferred year as part of a date states something the
/// log never said. A 2025 kubelet dump read in 2026 rendered `busiest
/// 2026-09-14`, which is simply a wrong date. Where the year is inferred we
/// print `MM-DD HH:MM` and claim only what the file carries.
fn carries_year(ts: &str) -> bool {
    // Maximal digit runs only. A sliding window finds "1812" inside klog's
    // ".181236" microseconds and would call a year-less stamp dated.
    let b = ts.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let run = &ts[start..i];
        match run.len() {
            // A bare 4-digit field is a year only if it reads as one; klog's
            // MMDD (`0909`) does not.
            4 => {
                if matches!(run.parse::<u32>(), Ok(1900..=2100)) {
                    return true;
                }
            }
            // An epoch is absolute, so its year is real rather than inferred.
            10 | 13 | 16 | 19 => return true,
            _ => {}
        }
    }
    false
}

/// `YYYY-MM-DD HH:MM` in UTC, for the busiest-bucket label — or `MM-DD HH:MM`
/// when the source timestamps carry no year of their own.
fn epoch_to_display(epoch: i64, dated: bool) -> String {
    let fmt = if dated {
        "%Y-%m-%d %H:%M"
    } else {
        "%m-%d %H:%M"
    };
    chrono::DateTime::from_timestamp(epoch, 0)
        .map_or_else(|| epoch.to_string(), |dt| dt.format(fmt).to_string())
}

fn render_format_line(f: &FormatSniff) -> String {
    let mut parts = Vec::new();
    let mut classes: Vec<(&str, usize)> =
        vec![("json", f.json), ("logfmt", f.logfmt), ("plain", f.plain)];
    classes.sort_by_key(|c| std::cmp::Reverse(c.1));
    let total = f.json + f.logfmt + f.plain;
    for (name, count) in classes {
        if count > 0 {
            let ratio = if total == 0 {
                0.0
            } else {
                count as f64 / total as f64 * 100.0
            };
            parts.push(format!(
                "{name} {} ({})",
                fmt_count(count),
                fmt_pct_whole(ratio)
            ));
        }
    }
    let mut line = format!("format:  {}", parts.join(", "));
    if f.mixed {
        line.push_str(" — mixed");
    }
    line
}

/// Whole-number percent (`100%`, not `100.0%`) — the format line's summary
/// stat is coarser than the per-item numbers elsewhere in the briefing.
fn fmt_pct_whole(value: f64) -> String {
    format!("{value:.0}%")
}

fn render_levels_line(levels: &Levels, total_lines: usize) -> String {
    if levels.lines_with_level == 0 {
        return "levels:  none detected".to_string();
    }
    let mut parts = Vec::new();
    for (name, count) in [
        ("fatal", levels.fatal),
        ("error", levels.error),
        ("warn", levels.warn),
        ("info", levels.info),
        ("debug", levels.debug),
        ("trace", levels.trace),
    ] {
        if count > 0 {
            let ratio = pct(count, levels.lines_with_level.max(1));
            parts.push(format!("{name} {} ({})", fmt_count(count), fmt_pct(ratio)));
        }
    }
    let coverage_pct = fmt_pct_whole(pct(levels.lines_with_level, total_lines));
    format!(
        "levels:  {} — on {} lines ({coverage_pct})",
        parts.join(", "),
        fmt_count(levels.lines_with_level)
    )
}

/// The count-over-span middle column: `in <1s` when every member landed in
/// the same second, `over 5h51m` when they didn't, nothing when no member
/// carried a parseable timestamp. Never a derived rate — a mean interval is
/// a false claim for a group that bursts and goes quiet, so this prints the
/// two honest facts (count, span) and leaves the division to the reader.
fn render_template_span(span_seconds: Option<u64>) -> String {
    match span_seconds {
        Some(0) => "in <1s".to_string(),
        Some(s) => format!("over {}", humanize_duration(s)),
        None => String::new(),
    }
}

fn render_templates_block(t: &TopTemplates) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "top templates ({} of {}, {} of all lines):\n",
        t.shown.len(),
        t.total_groups,
        fmt_pct(t.shown_share_pct)
    ));
    let pct_strs: Vec<String> = t.shown.iter().map(|e| fmt_pct(e.pct)).collect();
    let count_strs: Vec<String> = t.shown.iter().map(|e| fmt_count(e.count)).collect();
    let span_strs: Vec<String> = t
        .shown
        .iter()
        .map(|e| render_template_span(e.span_seconds))
        .collect();
    let pct_width = pct_strs.iter().map(String::len).max().unwrap_or(0);
    let count_width = count_strs.iter().map(String::len).max().unwrap_or(0);
    let span_width = span_strs.iter().map(String::len).max().unwrap_or(0);
    for (i, entry) in t.shown.iter().enumerate() {
        out.push_str(&format!(
            "   {:>pct_width$}  {:>count_width$}  {:<span_width$}  {}\n",
            pct_strs[i],
            count_strs[i],
            span_strs[i],
            truncate_chars(&entry.template, 100),
        ));
    }
    out
}

/// The `rare:` line after the top-templates block — principle 4, "rare is
/// signal": omitted entirely when nothing occurs exactly once.
fn render_rare_line(t: &TopTemplates) -> Option<String> {
    if t.singletons == 0 {
        return None;
    }
    Some(format!(
        "rare:    {} templates occur once ({} of lines)",
        fmt_count(t.singletons),
        fmt_pct(t.singleton_pct)
    ))
}

fn render_tokens_line(tokens: &[TokenClass]) -> String {
    let width = 100usize;
    let indent = " ".repeat(9);
    let n = tokens.len();
    let words: Vec<String> = tokens
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let tilde = if t.distinct_exact { "" } else { "~" };
            let core = format!(
                "{} {}/{tilde}{}",
                t.class,
                fmt_count(t.occurrences),
                fmt_count(t.distinct as usize)
            );
            if i + 1 < n { format!("{core},") } else { core }
        })
        .collect();

    let mut lines = Vec::new();
    let mut current = String::from("tokens:  ");
    let mut current_has_word = false;
    for word in words {
        let extra = if current_has_word {
            1 + word.chars().count()
        } else {
            word.chars().count()
        };
        if current_has_word && current.chars().count() + extra > width {
            lines.push(current);
            current = format!("{indent}{word}");
            current_has_word = true;
        } else {
            if current_has_word {
                current.push(' ');
            }
            current.push_str(&word);
            current_has_word = true;
        }
    }
    lines.push(current);
    lines.join("\n")
}

/// Render the whole stderr briefing footer, including the leading blank
/// line and both `---` delimiters.
pub fn render_text(b: &Briefing) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!(
        "--- lessence briefing: {} ({} lines)\n",
        b.source.as_deref().unwrap_or("stdin"),
        fmt_count(b.lines)
    ));
    out.push_str(&render_span_line(&b.span));
    out.push('\n');
    if let Some(hist) = &b.histogram
        && let Some(first) = &b.span.first
        && let Some(first_epoch) = epoch_seconds(first)
    {
        out.push_str(&render_shape_line(hist, first_epoch, carries_year(first)));
        out.push('\n');
    }
    out.push_str(&render_format_line(&b.format));
    out.push('\n');
    out.push_str(&render_levels_line(&b.levels, b.lines));
    out.push('\n');
    out.push_str(&render_templates_block(&b.templates));
    if let Some(rare) = render_rare_line(&b.templates) {
        out.push_str(&rare);
        out.push('\n');
    }
    if b.tokens.is_empty() {
        out.push_str("tokens:  none detected\n");
    } else {
        out.push_str(&render_tokens_line(&b.tokens));
        out.push('\n');
    }
    out.push_str("---\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_from_line_top_level_json_object_without_json_token() {
        // The regression this rule exists for: a well-formed JSON record
        // produces no Token::Json, and used to sniff as plain.
        let line = r#"{"level":"info","msg":"Loading TLS configuration"}"#;
        assert_eq!(format_from_line(&[], line), FormatClass::Json);
    }

    #[test]
    fn format_from_line_top_level_json_array() {
        assert_eq!(format_from_line(&[], r"[1,2,3]"), FormatClass::Json);
    }

    #[test]
    fn format_from_line_json_line_tolerates_surrounding_whitespace() {
        assert_eq!(format_from_line(&[], "  {\"a\":1}  "), FormatClass::Json);
    }

    #[test]
    fn format_from_line_open_brace_without_close_is_not_json() {
        // A prose line that merely starts with a brace is not a JSON record.
        assert_eq!(format_from_line(&[], "{ unterminated"), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_close_brace_without_open_is_not_json() {
        assert_eq!(format_from_line(&[], "trailing }"), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_mismatched_brackets_are_not_json() {
        assert_eq!(format_from_line(&[], "{1,2]"), FormatClass::Plain);
    }

    #[test]
    fn carries_year_true_for_iso8601() {
        assert!(carries_year("2025-09-20T09:10:38Z"));
    }

    #[test]
    fn carries_year_false_for_klog() {
        // `E0909 13:07:09.181236` — 0909 starts with 0, not a year.
        assert!(!carries_year("E0909 13:07:09.181236"));
    }

    #[test]
    fn carries_year_false_for_syslog_bsd() {
        assert!(!carries_year("Sep  9 13:07:09"));
    }

    #[test]
    fn carries_year_false_for_klog_microseconds() {
        // A sliding window finds "1812" inside ".181236"; only maximal runs
        // may be read as a year.
        assert!(!carries_year("E0909 13:07:09.181236"));
    }

    #[test]
    fn carries_year_false_for_four_digit_mmdd() {
        // klog's 0909 is four digits but not a plausible year.
        assert!(!carries_year("0909 13:07:09"));
    }

    #[test]
    fn carries_year_true_for_epoch_seconds() {
        assert!(carries_year("1757424429"));
    }

    #[test]
    fn carries_year_true_for_asctime() {
        assert!(carries_year("Sat Sep  9 13:07:09 2025"));
    }

    #[test]
    fn epoch_to_display_omits_year_when_not_carried() {
        let dated = epoch_to_display(1_757_424_429, true);
        let undated = epoch_to_display(1_757_424_429, false);
        assert!(dated.starts_with("2025-"), "{dated}");
        assert!(!undated.starts_with("2025-"), "{undated}");
        assert!(dated.ends_with(&undated), "{dated} should extend {undated}");
    }

    // -- format_from_line ---------------------------------------------
    //
    // Format used to be sniffed by re-scanning the raw line; it is now
    // read off the tokens the pipeline already produced. These tests
    // exercise `format_from_line` directly with constructed token
    // slices rather than raw strings.

    #[test]
    fn format_from_line_json_object() {
        let tokens = vec![Token::Json(r#"{"level":"error"}"#.to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_json_array() {
        let tokens = vec![Token::Json("[1, 2, 3]".to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_json_wins_regardless_of_token_order() {
        // Unlike the old leading-byte scan, a `Token::Json` decides the
        // format no matter where it sits among the line's other tokens.
        let tokens = vec![
            Token::Number("1".to_string()),
            Token::Json(r#"{"a":1}"#.to_string()),
        ];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_logfmt_two_pairs() {
        let tokens = vec![
            Token::KeyValuePair {
                key: "time".to_string(),
                value_type: "NUMBER".to_string(),
            },
            Token::KeyValuePair {
                key: "level".to_string(),
                value_type: "WORD".to_string(),
            },
        ];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Logfmt);
    }

    #[test]
    fn format_from_line_logfmt_needs_two_pairs_not_one() {
        let tokens = vec![Token::KeyValuePair {
            key: "level".to_string(),
            value_type: "WORD".to_string(),
        }];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_quoted_equals_not_counted_as_pairs() {
        // `msg="x=y z=w"` is a single `QuotedString`, not `KeyValuePair`s —
        // the detector already keeps the quoted `=` signs out of the
        // pair count, so there is nothing left here to re-derive.
        let tokens = vec![Token::QuotedString("x=y z=w".to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_plain_prose() {
        let tokens = vec![Token::Name("connection".to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_no_tokens_is_plain() {
        assert_eq!(format_from_line(&[], "plain prose"), FormatClass::Plain);
    }

    // -- classify_level -------------------------------------------------

    #[test]
    fn classify_level_klog_error() {
        assert_eq!(
            classify_level("E0909 13:07:09.181236    1 pod_workers.go:1301]"),
            Some(Level::Error)
        );
    }

    #[test]
    fn classify_level_klog_warn() {
        assert_eq!(classify_level("W0920 14:52:55.728948"), Some(Level::Warn));
    }

    #[test]
    fn classify_level_klog_info() {
        assert_eq!(classify_level("I0909 00:00:00.000000"), Some(Level::Info));
    }

    #[test]
    fn classify_level_klog_fatal() {
        assert_eq!(classify_level("F0909 00:00:00.000000"), Some(Level::Fatal));
    }

    #[test]
    fn classify_level_bracketed() {
        assert_eq!(
            classify_level("[ERROR] connection refused"),
            Some(Level::Error)
        );
    }

    #[test]
    fn classify_level_bracketed_case_insensitive() {
        assert_eq!(classify_level("[warn] retrying"), Some(Level::Warn));
    }

    #[test]
    fn classify_level_field_level_equals() {
        assert_eq!(
            classify_level("time=2024 level=debug msg=hi"),
            Some(Level::Debug)
        );
    }

    #[test]
    fn classify_level_field_severity_equals() {
        assert_eq!(classify_level("severity=CRITICAL x=1"), Some(Level::Fatal));
    }

    #[test]
    fn classify_level_field_json_level_key() {
        assert_eq!(
            classify_level(r#"{"level":"info","msg":"ok"}"#),
            Some(Level::Info)
        );
    }

    #[test]
    fn classify_level_standalone_caps() {
        assert_eq!(
            classify_level("something bad happened ERROR during startup"),
            Some(Level::Error)
        );
    }

    #[test]
    fn classify_level_standalone_caps_rejects_mixed_case() {
        // "Error" is not ALL-CAPS, and matches none of the other shapes.
        assert_eq!(classify_level("an Error occurred here today"), None);
    }

    #[test]
    fn classify_level_none_when_no_shape_matches() {
        assert_eq!(classify_level("connection refused by peer"), None);
    }

    #[test]
    fn classify_level_only_scans_first_64_bytes() {
        let padding = "x".repeat(100);
        let line = format!("{padding} ERROR");
        assert_eq!(classify_level(&line), None);
    }

    #[test]
    fn classify_level_fatal_word_variants() {
        for word in ["FATAL", "CRIT", "CRITICAL", "EMERG", "EMERGENCY", "PANIC"] {
            assert_eq!(
                classify_level(&format!("[{word}]")),
                Some(Level::Fatal),
                "word {word} should map to Fatal"
            );
        }
    }

    #[test]
    fn classify_level_trace_word() {
        assert_eq!(classify_level("[TRACE]"), Some(Level::Trace));
    }

    // -- level_from_tokens ------------------------------------------------
    //
    // The free cases: a level read off a token rather than scanned from
    // raw bytes. Each test's raw `line` argument deliberately carries no
    // scannable level of its own, so a `Some` result proves the token
    // path — not the `classify_level` fallback — supplied it.

    #[test]
    fn level_from_tokens_klog_letter_in_timestamp_token() {
        let tokens = vec![Token::Timestamp("E0909 13:07:09.181236".to_string())];
        assert_eq!(
            level_from_tokens(&tokens, "1 pod_workers.go:1301]"),
            Some(Level::Error)
        );
    }

    #[test]
    fn level_from_tokens_klog_letter_covers_all_four() {
        for (letter, level) in [
            ('E', Level::Error),
            ('W', Level::Warn),
            ('I', Level::Info),
            ('F', Level::Fatal),
        ] {
            let ts = format!("{letter}0920 14:52:55.728948");
            let tokens = vec![Token::Timestamp(ts)];
            assert_eq!(level_from_tokens(&tokens, "no level here"), Some(level));
        }
    }

    #[test]
    fn level_from_tokens_log_with_module() {
        let tokens = vec![Token::LogWithModule {
            level: "WARN".to_string(),
            module: "transport".to_string(),
        }];
        assert_eq!(
            level_from_tokens(&tokens, "no scannable level"),
            Some(Level::Warn)
        );
    }

    #[test]
    fn level_from_tokens_structured_message() {
        let tokens = vec![Token::StructuredMessage {
            component: "web".to_string(),
            level: "debug".to_string(),
        }];
        assert_eq!(
            level_from_tokens(&tokens, "no scannable level"),
            Some(Level::Debug)
        );
    }

    #[test]
    fn level_from_tokens_bracket_context() {
        let tokens = vec![Token::BracketContext(vec![
            "worker-1".to_string(),
            "CRITICAL".to_string(),
        ])];
        assert_eq!(
            level_from_tokens(&tokens, "no scannable level"),
            Some(Level::Fatal)
        );
    }

    #[test]
    fn level_from_tokens_falls_back_to_byte_scan() {
        // No token carries a level; the raw line does, via `classify_level`.
        let tokens = vec![Token::Path("/var/log/app.log".to_string())];
        assert_eq!(
            level_from_tokens(&tokens, "[ERROR] connection refused"),
            Some(Level::Error)
        );
    }

    #[test]
    fn level_from_tokens_none_anywhere_is_none() {
        let tokens = vec![Token::Path("/var/log/app.log".to_string())];
        assert_eq!(
            level_from_tokens(&tokens, "connection refused by peer"),
            None
        );
    }

    // -- CardinalityEstimator (lessence-nn3) -------------------------------

    #[test]
    fn cardinality_exact_below_boundary() {
        let mut est = CardinalityEstimator::default();
        for i in 0..500u64 {
            est.insert(i);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), 500);
    }

    #[test]
    fn cardinality_duplicates_do_not_inflate_exact_count() {
        let mut est = CardinalityEstimator::default();
        for _ in 0..10 {
            est.insert(42);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), 1);
    }

    #[test]
    fn cardinality_conversion_at_boundary_preserves_count() {
        let mut est = CardinalityEstimator::default();
        for i in 0..CARDINALITY_EXACT_CAP as u64 {
            est.insert(i);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), CARDINALITY_EXACT_CAP as u64);

        // The insert that pushes past the cap converts to HLL.
        est.insert(CARDINALITY_EXACT_CAP as u64);
        assert!(!est.is_exact());
        // The true count (cap + 1) is known exactly at conversion time; the
        // clamp in `hll_estimate` guarantees the estimate never reports
        // below that, so this exact value is not a coincidence.
        assert_eq!(est.distinct(), CARDINALITY_EXACT_CAP as u64 + 1);
    }

    #[test]
    fn cardinality_large_set_estimates_within_a_few_percent() {
        let mut est = CardinalityEstimator::default();
        let true_count = 100_000u64;
        for i in 0..true_count {
            // Spread inputs across the u64 space the way a real hash would,
            // rather than feeding the estimator small sequential integers.
            est.insert(splitmix64(i));
        }
        assert!(!est.is_exact());
        let estimate = est.distinct();
        let error = (estimate as f64 - true_count as f64).abs() / true_count as f64;
        assert!(
            error < 0.05,
            "estimate {estimate} vs true {true_count}, error {error:.4}"
        );
    }

    #[test]
    fn cardinality_deterministic_across_runs() {
        let make = || {
            let mut est = CardinalityEstimator::default();
            for i in 0..10_000u64 {
                est.insert(splitmix64(i));
            }
            est.distinct()
        };
        assert_eq!(make(), make());
    }

    /// splitmix64: a well-mixed, fully deterministic 64-bit hash from a
    /// sequential seed, used only to feed the cardinality estimator tests
    /// realistic-looking hash inputs instead of small sequential integers.
    fn splitmix64(seed: u64) -> u64 {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    // -- TemplateCounts ---------------------------------------------------

    #[test]
    fn template_counts_accumulates_fragmented_flush() {
        // lessence-940: the same template can flush twice as its group
        // fragments across evictions. Recording it twice must sum, not
        // overwrite or duplicate as two entries.
        let mut tc = TemplateCounts::default();
        tc.record("connection <VARIES>", 5, None, None);
        tc.record("connection <VARIES>", 7, None, None);
        let top = tc.build(12);
        assert_eq!(top.total_groups, 1);
        assert_eq!(top.shown[0].count, 12);
        assert_eq!(tc.total_members(), 12);
    }

    #[test]
    fn template_counts_cap_truncates_new_templates() {
        let mut tc = TemplateCounts::default();
        for i in 0..TEMPLATE_CAP {
            tc.record(&format!("template-{i}"), 1, None, None);
        }
        assert!(!tc.is_truncated());
        tc.record("one-too-many", 1, None, None);
        assert!(tc.is_truncated());
        assert_eq!(tc.build(TEMPLATE_CAP + 1).total_groups, TEMPLATE_CAP);
    }

    #[test]
    fn template_counts_cap_keeps_updating_existing_keys() {
        let mut tc = TemplateCounts::default();
        for i in 0..TEMPLATE_CAP {
            tc.record(&format!("template-{i}"), 1, None, None);
        }
        tc.record("one-too-many", 1, None, None); // dropped, sets truncated
        tc.record("template-0", 41, None, None); // existing key still accumulates
        assert_eq!(tc.build(TEMPLATE_CAP + 42).total_groups, TEMPLATE_CAP);
        assert_eq!(tc.total_members(), TEMPLATE_CAP + 41);
    }

    #[test]
    fn template_counts_ties_break_by_template_ascending() {
        let mut tc = TemplateCounts::default();
        tc.record("zzz", 3, None, None);
        tc.record("aaa", 3, None, None);
        let top = tc.build(6);
        assert_eq!(top.shown[0].template, "aaa");
        assert_eq!(top.shown[1].template, "zzz");
    }

    // -- render_text --------------------------------------------------

    fn fixture_briefing() -> Briefing {
        Briefing {
            source: Some("kubelet.log".to_string()),
            lines: 3951,
            span: Span {
                first: Some("E0909 13:07:09.181236".to_string()),
                last: Some("E0920 14:52:55.728948".to_string()),
                duration_seconds: None,
                lines_per_second: None,
            },
            format: FormatSniff {
                json: 0,
                logfmt: 0,
                plain: 3951,
                dominant: "plain",
                mixed: false,
            },
            levels: Levels {
                fatal: 0,
                error: 2190,
                warn: 412,
                info: 1349,
                debug: 0,
                trace: 0,
                lines_with_level: 3951,
            },
            templates: TopTemplates {
                total_groups: 205,
                shown: vec![
                    TemplateEntry {
                        count: 1205,
                        pct: 1205.0 / 3951.0 * 100.0,
                        template: "E<TIMESTAMP> <PID> pod_workers.go:1301] \"Error syncing pod, skipping\" err=…".to_string(),
                        first_epoch: None,
                        last_epoch: None,
                        span_seconds: None,
                    },
                    TemplateEntry {
                        count: 320,
                        pct: 320.0 / 3951.0 * 100.0,
                        template: "W<TIMESTAMP> <PID> transport.go:356] Unable to cancel request for …".to_string(),
                        first_epoch: None,
                        last_epoch: None,
                        span_seconds: None,
                    },
                ],
                shown_share_pct: 71.2,
                truncated: false,
                singletons: 0,
                singleton_pct: 0.0,
            },
            tokens: vec![
                TokenClass {
                    class: "timestamps",
                    occurrences: 6063,
                    distinct: 3940,
                    distinct_exact: true,
                },
                TokenClass {
                    class: "uuids",
                    occurrences: 5352,
                    distinct: 3000,
                    distinct_exact: false,
                },
            ],
            histogram: None,
        }
    }

    #[test]
    fn render_text_includes_header_with_source_and_lines() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains("--- lessence briefing: kubelet.log (3,951 lines)"));
    }

    #[test]
    fn render_text_span_shows_arrow_between_timestamps() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains("span:    E0909 13:07:09.181236 \u{2192} E0920 14:52:55.728948"));
    }

    #[test]
    fn render_text_span_no_timestamps_message() {
        let mut b = fixture_briefing();
        b.span = Span::default();
        let out = render_text(&b);
        assert!(out.contains("span:    (no timestamps detected)"));
    }

    #[test]
    fn render_text_format_all_plain_hundred_percent_no_decimal() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains("format:  plain 3,951 (100%)"));
    }

    #[test]
    fn render_text_levels_line_matches_expected_shape() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains(
            "levels:  error 2,190 (55.4%), warn 412 (10.4%), info 1,349 (34.1%) — on 3,951 lines (100%)"
        ));
    }

    #[test]
    fn render_text_levels_none_detected() {
        let mut b = fixture_briefing();
        b.levels = Levels::default();
        let out = render_text(&b);
        assert!(out.contains("levels:  none detected"));
    }

    #[test]
    fn render_text_top_templates_header() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains("top templates (2 of 205, 71.2% of all lines):"));
    }

    #[test]
    fn render_text_template_line_truncates_long_template() {
        let mut b = fixture_briefing();
        b.templates.shown[0].template = "x".repeat(150);
        let out = render_text(&b);
        let truncated = format!("{}…", "x".repeat(100));
        assert!(out.contains(&truncated));
        assert!(!out.contains(&"x".repeat(101)));
    }

    #[test]
    fn render_text_tokens_line_lists_classes() {
        let out = render_text(&fixture_briefing());
        assert!(out.contains("tokens:  timestamps 6,063/3,940, uuids 5,352/~3,000"));
    }

    #[test]
    fn render_text_keeps_delimiters() {
        let out = render_text(&fixture_briefing());
        assert!(out.starts_with("\n---"));
        assert!(out.trim_end().ends_with("---"));
    }

    #[test]
    fn fmt_count_groups_thousands() {
        assert_eq!(fmt_count(3951), "3,951");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000_000), "1,000,000");
    }

    #[test]
    fn fmt_pct_strips_trailing_zero_decimal() {
        assert_eq!(fmt_pct(100.0), "100%");
        assert_eq!(fmt_pct(55.44), "55.4%");
    }

    // -- epoch_seconds ------------------------------------------------

    #[test]
    fn epoch_seconds_bare_10_digit_is_seconds() {
        // 2025-09-09T13:07:09Z
        assert_eq!(epoch_seconds("1757423229"), Some(1_757_423_229));
    }

    #[test]
    fn epoch_seconds_bare_13_digit_is_millis() {
        assert_eq!(epoch_seconds("1757423229000"), Some(1_757_423_229));
    }

    #[test]
    fn epoch_seconds_bare_16_digit_is_micros() {
        assert_eq!(epoch_seconds("1757423229000000"), Some(1_757_423_229));
    }

    #[test]
    fn epoch_seconds_bare_19_digit_is_nanos() {
        assert_eq!(epoch_seconds("1757423229000000000"), Some(1_757_423_229));
    }

    #[test]
    fn epoch_seconds_klog_uses_current_utc_year() {
        let got = epoch_seconds("E0909 13:07:09.181236").unwrap();
        let expected = ymd_hms_to_epoch(current_utc_year(), 9, 9, 13, 7, 9).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn epoch_seconds_iso8601_t_separator() {
        assert_eq!(
            epoch_seconds("2025-09-09T13:07:09"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_iso8601_space_separator() {
        assert_eq!(
            epoch_seconds("2025-09-09 13:07:09"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_slash_date() {
        assert_eq!(
            epoch_seconds("2025/09/09 13:07:09"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_apache_clf() {
        assert_eq!(
            epoch_seconds("09/Sep/2025:13:07:09"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_syslog_bsd_no_year_uses_current_utc_year() {
        let got = epoch_seconds("Sep  9 13:07:09").unwrap();
        let expected = ymd_hms_to_epoch(current_utc_year(), 9, 9, 13, 7, 9).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn epoch_seconds_asctime_with_weekday_and_year() {
        assert_eq!(
            epoch_seconds("Tue Sep 9 13:07:09 2025"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_compact() {
        assert_eq!(
            epoch_seconds("20250909T130709"),
            ymd_hms_to_epoch(2025, 9, 9, 13, 7, 9)
        );
    }

    #[test]
    fn epoch_seconds_rejects_unrecognized_shape() {
        assert_eq!(epoch_seconds("not a timestamp"), None);
    }

    #[test]
    fn epoch_seconds_rejects_empty_string() {
        assert_eq!(epoch_seconds(""), None);
    }

    #[test]
    fn epoch_seconds_rejects_bad_all_digit_length() {
        // 11 digits matches none of the four accepted widths.
        assert_eq!(epoch_seconds("12345678901"), None);
    }

    #[test]
    fn epoch_seconds_rejects_invalid_calendar_date() {
        // Month 13 is not a real month.
        assert_eq!(epoch_seconds("2025-13-09T13:07:09"), None);
    }

    #[test]
    fn span_duration_seconds_same_shape_returns_difference() {
        assert_eq!(
            span_duration_seconds("2025-09-09T13:07:09", "2025-09-09T14:07:09"),
            Some(3600)
        );
    }

    #[test]
    fn span_duration_seconds_year_less_new_year_wrap_rolls_last_forward() {
        // Both stamped with the current year; "first" in late December and
        // "last" in early January reads as last < first unless the wrap
        // rule rolls last forward a year.
        let duration = span_duration_seconds("Dec 31 23:00:00", "Jan  1 01:00:00").unwrap();
        assert_eq!(duration, 2 * 3600);
    }

    #[test]
    fn span_duration_seconds_none_when_unparseable() {
        assert_eq!(
            span_duration_seconds("garbage", "2025-09-09T13:07:09"),
            None
        );
    }

    // -- humanize_duration ---------------------------------------------

    #[test]
    fn humanize_duration_two_largest_units() {
        assert_eq!(humanize_duration(11 * 86_400 + 3_600), "11d 1h");
        assert_eq!(humanize_duration(47), "47s");
        assert_eq!(humanize_duration(0), "0s");
    }

    // -- TopTemplates: tokens filter and ordering (step 7) --------------
    //
    // The actual filter+sort lives in `folder::render::build_briefing`
    // (it needs `FoldingStats::token_classes`, not reachable from this
    // module); `filter_and_sort_tokens` here is the exact same two-line
    // shape so the invariant is proven independently of that call site.

    fn filter_and_sort_tokens(mut tokens: Vec<TokenClass>) -> Vec<TokenClass> {
        tokens.retain(|t| t.occurrences > 0);
        tokens.sort_by(|a, b| {
            b.occurrences
                .cmp(&a.occurrences)
                .then_with(|| a.class.cmp(b.class))
        });
        tokens
    }

    #[test]
    fn tokens_zero_count_class_is_absent() {
        let tokens = filter_and_sort_tokens(vec![
            TokenClass {
                class: "timestamps",
                occurrences: 5,
                distinct: 5,
                distinct_exact: true,
            },
            TokenClass {
                class: "uuids",
                occurrences: 0,
                distinct: 0,
                distinct_exact: true,
            },
        ]);
        assert!(tokens.iter().all(|t| t.class != "uuids"));
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn tokens_ordered_by_occurrences_descending_then_class_ascending() {
        let tokens = filter_and_sort_tokens(vec![
            TokenClass {
                class: "uuids",
                occurrences: 5,
                distinct: 5,
                distinct_exact: true,
            },
            TokenClass {
                class: "paths",
                occurrences: 5,
                distinct: 5,
                distinct_exact: true,
            },
            TokenClass {
                class: "timestamps",
                occurrences: 10,
                distinct: 10,
                distinct_exact: true,
            },
        ]);
        assert_eq!(
            tokens.iter().map(|t| t.class).collect::<Vec<_>>(),
            vec!["timestamps", "paths", "uuids"]
        );
    }

    // -- TopTemplates: singletons ("rare is signal") --------------------

    #[test]
    fn template_counts_singletons_counted_and_percented() {
        let mut tc = TemplateCounts::default();
        tc.record("a", 1, None, None);
        tc.record("b", 1, None, None);
        tc.record("c", 3, None, None);
        let top = tc.build(5);
        assert_eq!(top.singletons, 2);
        assert!((top.singleton_pct - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn render_rare_line_absent_when_no_singletons() {
        let t = TopTemplates {
            total_groups: 1,
            shown: vec![],
            shown_share_pct: 0.0,
            truncated: false,
            singletons: 0,
            singleton_pct: 0.0,
        };
        assert!(render_rare_line(&t).is_none());
    }
}
