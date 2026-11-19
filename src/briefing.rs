use ahash::{AHashMap, AHashSet};
use serde::Serialize;

use crate::patterns::Token;

const TOP_TEMPLATES_TRACKED_CAP: usize = 8192;

const LEVEL_FALLBACK_SCAN_BYTES: usize = 64;

const TOP_TEMPLATES_SHOWN: usize = 10;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Briefing {
    pub source: Option<String>,
    pub lines: usize,
    pub span: Span,
    pub format: FormatSniff,
    pub levels: Levels,
    pub templates: TopTemplates,
    pub tokens: Vec<TokenClass>,
    pub histogram: Option<Histogram>,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Span {
    pub first: Option<String>,
    pub last: Option<String>,
    pub duration_seconds: Option<u64>,
    pub lines_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year_inferred: Option<bool>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Histogram {
    pub bucket_seconds: u64,
    pub buckets: Vec<u64>,
    pub busiest_index: usize,
    pub busiest_count: u64,
    pub busiest_pct: f64,
}

#[derive(Debug, Default)]
pub struct HistogramBuilder {
    bucket_seconds: u64,
    buckets: AHashMap<i64, u64>,
}

pub(crate) const HISTOGRAM_BUCKET_CAP: usize = 4096;

impl HistogramBuilder {
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

    pub(crate) fn grid(&self, first_epoch: i64, last_epoch: i64) -> Option<Grid> {
        if self.buckets.is_empty() {
            return None;
        }
        const DISPLAY_BUCKETS: i64 = 24;
        let span = (last_epoch - first_epoch).max(0);
        let display_bucket_seconds = (span / DISPLAY_BUCKETS + 1).max(self.bucket_seconds as i64);
        let num_buckets = (span / display_bucket_seconds + 1).clamp(1, DISPLAY_BUCKETS) as usize;
        Some(Grid {
            origin: first_epoch,
            bucket_seconds: display_bucket_seconds,
            len: num_buckets,
            collected_seconds: self.bucket_seconds,
        })
    }

    pub fn build(&self, first_epoch: i64, last_epoch: i64) -> Option<Histogram> {
        let grid = self.grid(first_epoch, last_epoch)?;
        let display_bucket_seconds = grid.bucket_seconds;
        let mut buckets = vec![0u64; grid.len];
        for (&key, &count) in &self.buckets {
            buckets[grid.index(key)] += count;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Grid {
    pub origin: i64,
    pub bucket_seconds: i64,
    pub len: usize,
    pub collected_seconds: u64,
}

impl Grid {
    pub(crate) fn index(&self, key: i64) -> usize {
        self.index_at(key * self.collected_seconds as i64)
    }

    pub(crate) fn index_at(&self, start: i64) -> usize {
        let offset = (start - self.origin).max(0);
        ((offset / self.bucket_seconds) as usize).min(self.len - 1)
    }
}

pub(crate) fn bunched_clause(pct: u64, from: &str, to: &str) -> String {
    format!("{pct}% in {from}\u{2013}{to}")
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
    pub span_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenClass {
    pub class: &'static str,
    pub occurrences: usize,
    pub distinct: Distinct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distinct {
    Exact(u64),
    Estimated(u64),
}

impl Distinct {
    pub fn value(self) -> u64 {
        match self {
            Self::Exact(n) | Self::Estimated(n) => n,
        }
    }

    pub fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

impl Serialize for TokenClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut record = serializer.serialize_struct("TokenClass", 4)?;
        record.serialize_field("class", self.class)?;
        record.serialize_field("occurrences", &self.occurrences)?;
        record.serialize_field("distinct", &self.distinct.value())?;
        record.serialize_field("distinct_exact", &self.distinct.is_exact())?;
        record.end()
    }
}

pub(crate) fn token_classes_by_occurrence(
    classes: impl IntoIterator<Item = TokenClass>,
) -> Vec<TokenClass> {
    let mut tokens: Vec<TokenClass> = classes.into_iter().filter(|t| t.occurrences > 0).collect();
    tokens.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then_with(|| a.class.cmp(b.class))
    });
    tokens
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatClass {
    Json,
    Logfmt,
    Plain,
}

fn is_json_line(line: &str) -> bool {
    let t = line.trim();
    let b = t.as_bytes();
    matches!(
        (b.first(), b.last()),
        (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']'))
    )
}

pub(crate) fn format_from_line(tokens: &[Token], line: &str) -> FormatClass {
    if is_json_line(line) || tokens.iter().any(|t| matches!(t, Token::EmbeddedJson(_))) {
        return FormatClass::Json;
    }
    const LOGFMT_MIN_KEY_VALUE_TOKENS: usize = 2;
    let kv_pairs = tokens
        .iter()
        .filter(|t| matches!(t, Token::KeyValuePair { .. }))
        .count();
    if kv_pairs >= LOGFMT_MIN_KEY_VALUE_TOKENS {
        FormatClass::Logfmt
    } else {
        FormatClass::Plain
    }
}

pub(crate) fn level_from_tokens(tokens: &[Token], line: &str) -> Option<Level> {
    klog_letter_in_a_timestamp_token(tokens)
        .or_else(|| level_field_of_a_module_or_structured_token(tokens))
        .or_else(|| level_word_in_a_bracket_context(tokens))
        .or_else(|| classify_level(line))
}

fn klog_letter_in_a_timestamp_token(tokens: &[Token]) -> Option<Level> {
    tokens.iter().find_map(|token| match token {
        Token::Timestamp(s) => klog_header_level(s.as_bytes()),
        _ => None,
    })
}

fn level_field_of_a_module_or_structured_token(tokens: &[Token]) -> Option<Level> {
    tokens.iter().find_map(|token| match token {
        Token::LogWithModule { level, .. } | Token::StructuredMessage { level, .. } => {
            word_to_level(level.as_bytes())
        }
        _ => None,
    })
}

fn level_word_in_a_bracket_context(tokens: &[Token]) -> Option<Level> {
    tokens.iter().find_map(|token| match token {
        Token::BracketContext(parts) => {
            parts.iter().find_map(|part| word_to_level(part.as_bytes()))
        }
        _ => None,
    })
}

#[derive(Default)]
struct LevelScan {
    bracket_level: Option<Level>,
    level_eq: Option<Level>,
    severity_eq: Option<Level>,
    level_key: Option<Level>,
    caps_level: Option<Level>,
}

impl LevelScan {
    fn in_priority_order(&self) -> [Option<Level>; 5] {
        [
            self.bracket_level,
            self.level_eq,
            self.severity_eq,
            self.level_key,
            self.caps_level,
        ]
    }

    fn found(&self) -> bool {
        self.in_priority_order().iter().any(Option::is_some)
    }

    fn level(&self) -> Option<Level> {
        self.in_priority_order().into_iter().flatten().next()
    }
}

fn scan_level_at(window: &[u8], i: usize, b: u8, scan: &mut LevelScan) {
    if scan.bracket_level.is_none()
        && b == b'['
        && let Some(close) = window[i + 1..].iter().position(|&c| c == b']')
    {
        let inner = &window[i + 1..i + 1 + close];
        scan.bracket_level = word_to_level(inner);
    }

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

fn scan_level(window: &[u8]) -> Option<Level> {
    let mut scan = LevelScan::default();
    let mut i = 0usize;
    while i < window.len() && !scan.found() {
        scan_level_at(window, i, window[i], &mut scan);
        i += 1;
    }
    scan.level()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub fn classify_level(line: &str) -> Option<Level> {
    let bytes = line.as_bytes();
    let window = &bytes[..bytes.len().min(LEVEL_FALLBACK_SCAN_BYTES)];
    klog_header_level(window).or_else(|| scan_level(window))
}

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

pub(crate) fn word_to_level(word: &[u8]) -> Option<Level> {
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

const CARDINALITY_EXACT_CAP: usize = 2048;

const HLL_P: u32 = 10;
const HLL_M: usize = 1 << HLL_P;

#[derive(Debug, Clone)]
enum CardinalityState {
    Exact(AHashSet<u64>),
    Hll(Box<[u8; HLL_M]>),
}

#[derive(Debug, Clone)]
pub struct ExactThenHll {
    state: CardinalityState,
}

impl Default for ExactThenHll {
    fn default() -> Self {
        Self {
            state: CardinalityState::Exact(AHashSet::new()),
        }
    }
}

impl ExactThenHll {
    pub fn insert(&mut self, hash: u64) {
        match &mut self.state {
            CardinalityState::Exact(set) => {
                if set.contains(&hash) {
                    return;
                }
                if set.len() < CARDINALITY_EXACT_CAP {
                    set.insert(hash);
                } else {
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

    pub fn is_exact(&self) -> bool {
        matches!(self.state, CardinalityState::Exact(_))
    }

    pub fn distinct(&self) -> u64 {
        self.distinct_count().value()
    }

    pub fn distinct_count(&self) -> Distinct {
        match &self.state {
            CardinalityState::Exact(set) => Distinct::Exact(set.len() as u64),
            CardinalityState::Hll(registers) => Distinct::Estimated(hll_estimate(registers)),
        }
    }
}

fn hll_add(registers: &mut [u8; HLL_M], hash: u64) {
    let idx = (hash >> (64 - HLL_P)) as usize;
    let rest = hash << HLL_P;
    let rank = (rest.leading_zeros() + 1) as u8;
    if rank > registers[idx] {
        registers[idx] = rank;
    }
}

const _: () = assert!(HLL_M >= 128, "hll_alpha's formula holds only for m >= 128");

fn hll_alpha(m: f64) -> f64 {
    0.7213 / (1.0 + 1.079 / m)
}

fn hll_estimate(registers: &[u8; HLL_M]) -> u64 {
    let m = HLL_M as f64;
    let alpha = hll_alpha(m);
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

fn bare_epoch_units_per_second(digits: usize) -> Option<i64> {
    match digits {
        10 => Some(1),
        13 => Some(1_000),
        16 => Some(1_000_000),
        19 => Some(1_000_000_000),
        _ => None,
    }
}

pub(crate) fn epoch_seconds(ts: &str) -> Option<i64> {
    let trimmed = ts.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    if bytes.iter().all(u8::is_ascii_digit) {
        let n: i64 = trimmed.parse().ok()?;
        return bare_epoch_units_per_second(bytes.len()).map(|units| n / units);
    }

    parse_klog_epoch(bytes)
        .or_else(|| parse_iso_epoch(bytes))
        .or_else(|| parse_slash_date_epoch(bytes))
        .or_else(|| parse_clf_epoch(bytes))
        .or_else(|| parse_compact_epoch(bytes))
        .or_else(|| parse_syslog_or_asctime_epoch(trimmed))
}

fn d2(b: &[u8]) -> Option<u32> {
    if b.len() == 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
        Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
    } else {
        None
    }
}

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

fn process_utc_year() -> i32 {
    static YEAR: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *YEAR.get_or_init(|| {
        i32::from(
            jiff::tz::Offset::UTC
                .to_datetime(jiff::Timestamp::now())
                .year(),
        )
    })
}

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
        let date = jiff::civil::Date::new(
            i16::try_from(year).ok()?,
            i8::try_from(month).ok()?,
            i8::try_from(day).ok()?,
        )
        .ok()?;
        let epoch = jiff::tz::Offset::UTC
            .to_timestamp(date.to_datetime(jiff::civil::Time::midnight()))
            .ok()?
            .as_second();
        cell.set(Some((year, month, day, epoch)));
        Some(epoch)
    })?;
    Some(midnight + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
}

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
    ymd_hms_to_epoch(process_utc_year(), month, day, hour, min, sec)
}

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

fn parse_syslog_or_asctime_epoch(s: &str) -> Option<i64> {
    let mut fields = s.split_ascii_whitespace();
    let mut first = fields.next()?;
    let month = if let Some(m) = month_abbrev(first.as_bytes()) {
        m
    } else {
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
        _ => process_utc_year(),
    };
    ymd_hms_to_epoch(year, month, day, hour, min, sec)
}

fn add_one_year_utc(epoch: i64) -> Option<i64> {
    let utc = jiff::tz::Offset::UTC;
    let dt = utc.to_datetime(jiff::Timestamp::from_second(epoch).ok()?);
    let bumped_date =
        jiff::civil::Date::new(dt.year().checked_add(1)?, dt.month(), dt.day()).ok()?;
    Some(
        utc.to_timestamp(bumped_date.to_datetime(dt.time()))
            .ok()?
            .as_second(),
    )
}

pub(crate) fn span_epochs(first: &str, last: &str) -> Option<(i64, i64)> {
    let first_epoch = epoch_seconds(first)?;
    let mut last_epoch = epoch_seconds(last)?;
    if last_epoch < first_epoch {
        last_epoch = add_one_year_utc(last_epoch).unwrap_or(last_epoch);
    }
    Some((first_epoch, last_epoch))
}

pub(crate) fn span_year_inferred(first: Option<&str>, last: Option<&str>) -> Option<bool> {
    match (first, last) {
        (None, None) => None,
        (f, l) => Some(f.is_some_and(|t| !carries_year(t)) || l.is_some_and(|t| !carries_year(t))),
    }
}

pub(crate) fn span_duration_seconds(first: &str, last: &str) -> Option<u64> {
    let (first_epoch, last_epoch) = span_epochs(first, last)?;
    u64::try_from(last_epoch - first_epoch).ok()
}

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
        } else if self.map.len() < TOP_TEMPLATES_TRACKED_CAP {
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

    pub fn total_members(&self) -> usize {
        self.map.values().map(|a| a.count).sum()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn build(&self, total_lines: usize) -> TopTemplates {
        let mut entries: Vec<(&String, &TemplateAcc)> = self.map.iter().collect();
        entries.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));

        let shown: Vec<TemplateEntry> = entries
            .into_iter()
            .take(TOP_TEMPLATES_SHOWN)
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

fn fmt_pct(value: f64) -> String {
    let s = format!("{value:.1}%");
    s.strip_suffix(".0%")
        .map_or(s.clone(), |head| format!("{head}%"))
}

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

const HUMANIZED_LARGEST_UNITS: usize = 2;

fn humanize_duration(mut seconds: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)];
    let mut parts = Vec::new();
    for (name, unit_seconds) in UNITS {
        if seconds >= unit_seconds {
            parts.push(format!("{}{name}", seconds / unit_seconds));
            seconds %= unit_seconds;
        }
        if parts.len() == HUMANIZED_LARGEST_UNITS {
            break;
        }
    }
    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

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

pub(crate) fn carries_year(ts: &str) -> bool {
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
            4 => {
                if is_plausible_year(run) {
                    return true;
                }
            }
            digits if bare_epoch_units_per_second(digits).is_some() => return true,
            _ => {}
        }
    }
    false
}

fn is_plausible_year(four_digits: &str) -> bool {
    matches!(four_digits.parse::<u32>(), Ok(1900..=2100))
}

fn epoch_to_display(epoch: i64, dated: bool) -> String {
    let fmt = if dated {
        "%Y-%m-%d %H:%M"
    } else {
        "%m-%d %H:%M"
    };
    jiff::Timestamp::from_second(epoch)
        .map_or_else(|_| epoch.to_string(), |ts| ts.strftime(fmt).to_string())
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
            let tilde = if t.distinct.is_exact() { "" } else { "~" };
            let core = format!(
                "{} {}/{tilde}{}",
                t.class,
                fmt_count(t.occurrences),
                fmt_count(t.distinct.value() as usize)
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
    fn add_one_year_utc_has_no_29_february_in_a_non_leap_year() {
        assert_eq!(add_one_year_utc(1_709_208_000), None);
    }

    #[test]
    fn add_one_year_utc_keeps_month_day_and_clock() {
        assert_eq!(add_one_year_utc(1_757_423_229), Some(1_788_959_229));
    }

    #[test]
    fn ymd_hms_to_epoch_rejects_31_april() {
        assert_eq!(ymd_hms_to_epoch(2025, 4, 31, 0, 0, 0), None);
    }

    #[test]
    fn ymd_hms_to_epoch_rejects_29_february_in_a_non_leap_year() {
        assert_eq!(ymd_hms_to_epoch(2025, 2, 29, 0, 0, 0), None);
    }

    #[test]
    fn ymd_hms_to_epoch_accepts_29_february_in_a_leap_year() {
        assert_eq!(ymd_hms_to_epoch(2024, 2, 29, 0, 0, 0), Some(1_709_164_800));
    }

    #[test]
    fn format_from_line_top_level_json_object_without_json_token() {
        let line = r#"{"level":"info","msg":"Loading TLS configuration"}"#;
        assert_eq!(
            format_from_line(&[], line),
            FormatClass::Json,
            "a well-formed JSON record yields no Token::EmbeddedJson and used to sniff as plain"
        );
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
    fn carries_year_false_for_klog_mmdd_starting_with_zero() {
        assert!(!carries_year("E0909 13:07:09.181236"));
    }

    #[test]
    fn carries_year_false_for_syslog_bsd() {
        assert!(!carries_year("Sep  9 13:07:09"));
    }

    #[test]
    fn carries_year_false_for_klog_microseconds() {
        assert!(
            !carries_year("E0909 13:07:09.181236"),
            "a sliding window finds 1812 inside .181236"
        );
    }

    #[test]
    fn carries_year_false_for_four_digit_mmdd() {
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

    #[test]
    fn format_from_line_json_object() {
        let tokens = vec![Token::EmbeddedJson(r#"{"level":"error"}"#.to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_json_array() {
        let tokens = vec![Token::EmbeddedJson("[1, 2, 3]".to_string())];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_json_wins_regardless_of_token_order() {
        let tokens = vec![
            Token::Number("1".to_string()),
            Token::EmbeddedJson(r#"{"a":1}"#.to_string()),
        ];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Json);
    }

    #[test]
    fn format_from_line_logfmt_two_pairs() {
        let tokens = vec![
            Token::KeyValuePair {
                key: "time".to_string(),
                value_type: crate::patterns::ValueType::Number,
            },
            Token::KeyValuePair {
                key: "level".to_string(),
                value_type: crate::patterns::ValueType::Text,
            },
        ];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Logfmt);
    }

    #[test]
    fn format_from_line_logfmt_needs_two_pairs_not_one() {
        let tokens = vec![Token::KeyValuePair {
            key: "level".to_string(),
            value_type: crate::patterns::ValueType::Text,
        }];
        assert_eq!(format_from_line(&tokens, ""), FormatClass::Plain);
    }

    #[test]
    fn format_from_line_quoted_equals_not_counted_as_pairs() {
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

    #[test]
    fn level_from_tokens_klog_letter_in_timestamp_token() {
        let tokens = vec![Token::Timestamp("E0909 13:07:09.181236".to_string())];
        assert_eq!(
            level_from_tokens(&tokens, "1 pod_workers.go:1301]"),
            Some(Level::Error),
            "the raw line carries no scannable level, so Some proves the token path"
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
            assert_eq!(
                level_from_tokens(&tokens, "no level here"),
                Some(level),
                "the raw line carries no scannable level, so Some proves the token path"
            );
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
            Some(Level::Warn),
            "the raw line carries no scannable level, so Some proves the token path"
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
            Some(Level::Debug),
            "the raw line carries no scannable level, so Some proves the token path"
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
            Some(Level::Fatal),
            "the raw line carries no scannable level, so Some proves the token path"
        );
    }

    #[test]
    fn level_from_tokens_falls_back_to_byte_scan() {
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

    #[test]
    fn cardinality_exact_below_boundary() {
        let mut est = ExactThenHll::default();
        for i in 0..500u64 {
            est.insert(i);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), 500);
    }

    #[test]
    fn cardinality_duplicates_do_not_inflate_exact_count() {
        let mut est = ExactThenHll::default();
        for _ in 0..10 {
            est.insert(42);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), 1);
    }

    #[test]
    fn cardinality_conversion_at_boundary_preserves_count() {
        let mut est = ExactThenHll::default();
        for i in 0..CARDINALITY_EXACT_CAP as u64 {
            est.insert(i);
        }
        assert!(est.is_exact());
        assert_eq!(est.distinct(), CARDINALITY_EXACT_CAP as u64);

        est.insert(CARDINALITY_EXACT_CAP as u64);
        assert!(!est.is_exact());
        assert_eq!(
            est.distinct(),
            CARDINALITY_EXACT_CAP as u64 + 1,
            "the hll_estimate clamp guarantees cap+1 exactly"
        );
    }

    #[test]
    fn cardinality_large_set_estimates_within_a_few_percent() {
        let mut est = ExactThenHll::default();
        let true_count = 100_000u64;
        for i in 0..true_count {
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
            let mut est = ExactThenHll::default();
            for i in 0..10_000u64 {
                est.insert(splitmix64(i));
            }
            est.distinct()
        };
        assert_eq!(make(), make());
    }

    fn splitmix64(seed: u64) -> u64 {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn template_counts_sums_a_template_recorded_twice() {
        let mut tc = TemplateCounts::default();
        tc.record("connection <VARIES>", 5, None, None);
        tc.record("connection <VARIES>", 7, None, None);
        let top = tc.build(12);
        assert_eq!(top.total_groups, 1);
        assert_eq!(
            top.shown[0].count, 12,
            "two groups sharing a template under different anchors must sum"
        );
        assert_eq!(tc.total_members(), 12);
    }

    #[test]
    fn template_counts_cap_truncates_new_templates() {
        let mut tc = TemplateCounts::default();
        for i in 0..TOP_TEMPLATES_TRACKED_CAP {
            tc.record(&format!("template-{i}"), 1, None, None);
        }
        assert!(!tc.is_truncated());
        tc.record("one-too-many", 1, None, None);
        assert!(tc.is_truncated(), "new template dropped, sets truncated");
        assert_eq!(
            tc.build(TOP_TEMPLATES_TRACKED_CAP + 1).total_groups,
            TOP_TEMPLATES_TRACKED_CAP
        );
    }

    #[test]
    fn template_counts_cap_keeps_updating_existing_keys() {
        let mut tc = TemplateCounts::default();
        for i in 0..TOP_TEMPLATES_TRACKED_CAP {
            tc.record(&format!("template-{i}"), 1, None, None);
        }
        tc.record("one-too-many", 1, None, None);
        tc.record("template-0", 41, None, None);
        assert_eq!(
            tc.build(TOP_TEMPLATES_TRACKED_CAP + 42).total_groups,
            TOP_TEMPLATES_TRACKED_CAP,
            "new template dropped"
        );
        assert_eq!(
            tc.total_members(),
            TOP_TEMPLATES_TRACKED_CAP + 41,
            "existing key still accumulates"
        );
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

    fn fixture_briefing() -> Briefing {
        Briefing {
            source: Some("kubelet.log".to_string()),
            lines: 3951,
            span: Span {
                first: Some("E0909 13:07:09.181236".to_string()),
                last: Some("E0920 14:52:55.728948".to_string()),
                duration_seconds: None,
                lines_per_second: None,
                year_inferred: Some(true),
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
                    distinct: Distinct::Exact(3940),
                },
                TokenClass {
                    class: "uuids",
                    occurrences: 5352,
                    distinct: Distinct::Estimated(3000),
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

    #[test]
    fn epoch_seconds_bare_10_digit_is_seconds() {
        assert_eq!(
            epoch_seconds("1757423229"),
            Some(1_757_423_229),
            "2025-09-09T13:07:09Z"
        );
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
    fn epoch_seconds_klog_uses_process_utc_year() {
        let got = epoch_seconds("E0909 13:07:09.181236").unwrap();
        let expected = ymd_hms_to_epoch(process_utc_year(), 9, 9, 13, 7, 9).unwrap();
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
    fn epoch_seconds_syslog_bsd_no_year_uses_process_utc_year() {
        let got = epoch_seconds("Sep  9 13:07:09").unwrap();
        let expected = ymd_hms_to_epoch(process_utc_year(), 9, 9, 13, 7, 9).unwrap();
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
        assert_eq!(
            epoch_seconds("12345678901"),
            None,
            "11 digits matches none of 10/13/16/19"
        );
    }

    #[test]
    fn epoch_seconds_rejects_invalid_calendar_date() {
        assert_eq!(epoch_seconds("2025-13-09T13:07:09"), None, "month 13");
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

    #[test]
    fn humanize_duration_two_largest_units() {
        assert_eq!(humanize_duration(11 * 86_400 + 3_600), "11d 1h");
        assert_eq!(humanize_duration(47), "47s");
        assert_eq!(humanize_duration(0), "0s");
    }

    #[test]
    fn tokens_zero_count_class_is_absent() {
        let tokens = token_classes_by_occurrence(vec![
            TokenClass {
                class: "timestamps",
                occurrences: 5,
                distinct: Distinct::Exact(5),
            },
            TokenClass {
                class: "uuids",
                occurrences: 0,
                distinct: Distinct::Exact(0),
            },
        ]);
        assert!(tokens.iter().all(|t| t.class != "uuids"));
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn tokens_ordered_by_occurrences_descending_then_class_ascending() {
        let tokens = token_classes_by_occurrence(vec![
            TokenClass {
                class: "uuids",
                occurrences: 5,
                distinct: Distinct::Exact(5),
            },
            TokenClass {
                class: "paths",
                occurrences: 5,
                distinct: Distinct::Exact(5),
            },
            TokenClass {
                class: "timestamps",
                occurrences: 10,
                distinct: Distinct::Exact(10),
            },
        ]);
        assert_eq!(
            tokens.iter().map(|t| t.class).collect::<Vec<_>>(),
            vec!["timestamps", "paths", "uuids"]
        );
    }

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

    #[test]
    fn year_inferred_true_for_klog_span() {
        assert_eq!(
            span_year_inferred(Some("E0909 13:07:09.181236"), Some("E0920 14:52:55.728948")),
            Some(true)
        );
    }

    #[test]
    fn year_inferred_true_for_syslog_span() {
        assert_eq!(
            span_year_inferred(Some("Sep  9 13:07:09"), Some("Sep 10 01:00:00")),
            Some(true)
        );
    }

    #[test]
    fn year_inferred_false_for_iso_span() {
        assert_eq!(
            span_year_inferred(Some("2025-09-20T09:10:38Z"), Some("2025-09-21T09:10:38Z")),
            Some(false)
        );
    }

    #[test]
    fn year_inferred_true_when_only_one_endpoint_lacks_a_year() {
        assert_eq!(
            span_year_inferred(Some("2025-09-20T09:10:38Z"), Some("E0921 09:10:38.000001")),
            Some(true)
        );
        assert_eq!(
            span_year_inferred(Some("E0921 09:10:38.000001"), Some("2025-09-20T09:10:38Z")),
            Some(true)
        );
    }

    #[test]
    fn year_inferred_absent_without_a_span() {
        assert_eq!(span_year_inferred(None, None), None);
        let json = serde_json::to_value(Span::default()).unwrap();
        assert!(json.get("year_inferred").is_none(), "{json}");
    }

    #[test]
    fn year_inferred_serialises_as_bool() {
        let span = Span {
            first: Some("Sep  9 13:07:09".into()),
            year_inferred: Some(true),
            ..Span::default()
        };
        let json = serde_json::to_value(span).unwrap();
        assert_eq!(json["year_inferred"], serde_json::Value::Bool(true));
    }
}
