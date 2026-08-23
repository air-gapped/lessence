use anyhow::Result;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::time::Duration;

use crate::config::Config;
use crate::ingest::IngestReport;
use crate::normalize::Normalizer;
use crate::patterns::{LogLine, Token};

/// Apply PII masking to original text by replacing email addresses with `<EMAIL>` tokens
///
/// Takes the original log line text and detected tokens, returns masked text with
/// all Token::Email instances replaced with the literal `<EMAIL>` string.
///
/// # Arguments
/// * `original` - Original log line text (may contain email addresses)
/// * `tokens` - Detected pattern tokens (including Token::Email variants)
///
/// # Returns
/// Modified string with all detected emails replaced by `<EMAIL>` tokens
///
/// # Performance
/// O(n × m) where n = text length, m = email count
/// Expected overhead: <1% of total line processing time
pub fn apply_pii_masking(original: &str, tokens: &[Token]) -> String {
    let mut result = original.to_string();
    let mut email_ranges = Vec::new();

    // Collect all email token positions
    for token in tokens {
        if let Token::Email(email) = token {
            if email.is_empty() {
                continue;
            }
            // Find all occurrences of this email in original text
            let mut start = 0;
            while let Some(pos) = result[start..].find(email) {
                let abs_pos = start + pos;
                email_ranges.push((abs_pos, abs_pos + email.len()));
                let next = abs_pos + email.len();
                if next <= start {
                    break; // Defensive: loop must always advance
                }
                start = next;
            }
        }
    }

    // Sort ranges in reverse order (replace from end to preserve indices)
    email_ranges.sort_by_key(|r| std::cmp::Reverse(r.0));

    // Replace each email with <EMAIL> token
    for (start, end) in email_ranges {
        result.replace_range(start..end, "<EMAIL>");
    }

    result
}

#[derive(Debug)]
struct PatternGroup {
    lines: Vec<LogLine>,
    position: usize, // Position when first line was encountered
    /// Input line number of the first line in this group (1-indexed).
    /// Used by the JSON output path; ignored by text/markdown formatting.
    first_line_no: usize,
    /// Input line number of the most recently added line in this group.
    /// Updated on every add_line().
    last_line_no: usize,
    /// Source IDs for the representative lines. `SourceId::STDIN` means the
    /// input had no filename (stdin). IDs resolve through `PatternFolder`.
    first_source_id: SourceId,
    last_source_id: SourceId,
}

impl PatternGroup {
    fn new(line: LogLine, position: usize) -> Self {
        Self::new_at(line, position, LineLocation::new(SourceId::STDIN, position))
    }

    fn new_at(line: LogLine, position: usize, location: LineLocation) -> Self {
        Self {
            lines: vec![line],
            position,
            first_line_no: location.line_no,
            last_line_no: location.line_no,
            first_source_id: location.source_id,
            last_source_id: location.source_id,
        }
    }

    fn add_line(&mut self, line: LogLine, line_no: usize) {
        self.add_line_at(line, LineLocation::new(SourceId::STDIN, line_no));
    }

    fn add_line_at(&mut self, line: LogLine, location: LineLocation) {
        self.lines.push(line);
        self.last_line_no = location.line_no;
        self.last_source_id = location.source_id;
    }

    fn should_collapse(&self, min_collapse: usize) -> bool {
        self.lines.len() >= min_collapse
    }

    fn first(&self) -> &LogLine {
        &self.lines[0]
    }

    fn last(&self) -> &LogLine {
        &self.lines[self.lines.len() - 1]
    }

    fn count(&self) -> usize {
        self.lines.len()
    }
}

/// Compact handle for an input source. The sentinel value represents stdin,
/// whose original filename is unknowable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceId(u32);

impl SourceId {
    const STDIN: Self = Self(u32::MAX);
}

#[derive(Clone, Copy, Debug)]
struct LineLocation {
    source_id: SourceId,
    line_no: usize,
}

impl LineLocation {
    fn new(source_id: SourceId, line_no: usize) -> Self {
        Self { source_id, line_no }
    }
}

pub struct PatternFolder {
    config: Config,
    normalizer: Normalizer,
    /// Sized rayon pool honoring `--threads N` for N >= 2. `None` for
    /// single-threaded mode (`Some(1)`, no parallelism at all) and for
    /// auto-detect (`thread_count: None`, rayon's global default pool).
    thread_pool: Option<rayon::ThreadPool>,
    buffer: Vec<PatternGroup>,
    /// Representative-hash → buffer index. Lines that are exact-hash
    /// repeats of a group's representative (the overwhelmingly common case
    /// in fold-heavy logs) resolve in O(1) instead of scanning the buffer.
    /// Safe because a line whose hash equals group G's representative
    /// compares identically to how that representative compared when G was
    /// created — it already failed similarity against every group ahead of
    /// G, so the linear scan would land on G too. At most one buffered
    /// group can hold any representative hash (a hash-equal line always
    /// joins, never founds).
    group_index: ahash::AHashMap<u64, usize>,
    stats: FoldingStats,
    position_counter: usize,
    batch_buffer: Vec<String>,
    /// Exact locations parallel to `batch_buffer`, populated only by the
    /// JSON CLI path. Text-mode ingestion never allocates or writes here.
    batch_locations: Vec<LineLocation>,
    /// Source names are interned once per explicit input file. Groups retain
    /// compact IDs rather than cloning a path for every line.
    sources: Vec<String>,
    /// Rendered group entries buffered for the markdown document. Only
    /// fills in markdown mode; the document is assembled by
    /// `emit_markdown` at the end of the run.
    markdown_entries: Vec<String>,
    /// Monotonic counter for JSON group record `id` fields. Incremented
    /// exactly once per flushed group in JSON mode. Stays at 0 in text /
    /// markdown modes. Stable within a run.
    next_json_id: usize,
    json_input_complete: bool,
    json_max_lines_reached: bool,
    json_failed_sources: bool,
    json_skipped_overlong_lines: usize,
    json_groups_emitted: usize,
    json_groups_total: Option<usize>,
    json_omitted_by_top: usize,
    json_omitted_by_summary_cap: usize,
    json_omitted_by_fit: usize,
    json_capped_entries: usize,
    json_uncomputed_variation_groups: usize,
    json_sampled_entries: usize,
    json_omitted_values_lower_bound: usize,
    /// Rollup computer — runs on every group at flush time regardless of
    /// output format, so the perf gate applies uniformly to text and
    /// JSON modes. Parameters (K, distinct_cap) are calibrated against
    /// the full corpus; see `docs/rollup-calibration.md` for evidence.
    rollup_computer: RollupComputer,
}

#[derive(Debug, Default)]
pub struct FoldingStats {
    pub total_lines: usize,
    pub output_lines: usize, // Actual compressed output lines (excluding summary)
    pub collapsed_groups: usize,
    pub lines_saved: usize,
    pub patterns_detected: usize,
    // Pattern distribution counters — one per token category, no lumping.
    pub timestamps: usize,
    pub ips: usize,
    pub ports: usize,
    pub fqdns: usize,
    pub hashes: usize,
    pub uuids: usize,
    pub pids: usize,
    pub durations: usize,
    pub http_status: usize,
    pub sizes: usize,
    pub percentages: usize,
    pub paths: usize,
    pub json: usize,
    pub quoted_strings: usize,
    pub names: usize,
    pub brackets: usize,
    pub key_values: usize,
    pub log_modules: usize,
    pub structured: usize,
    pub kubernetes: usize,
    pub emails: usize,
}

impl FoldingStats {
    /// Every pattern category as (footer label, count, footer description).
    /// Single source of truth for the Pattern Distribution table and the
    /// active-category count, so a new counter cannot be forgotten in one
    /// place but not the other.
    fn pattern_counters(&self) -> [(&'static str, usize, &'static str); 21] {
        [
            (
                "Timestamps",
                self.timestamps,
                "Log timestamps, dates, times",
            ),
            ("IP Addresses", self.ips, "IPv4, IPv6, network addresses"),
            ("Ports", self.ports, "Network port numbers"),
            ("Hostnames", self.fqdns, "Fully-qualified domain names"),
            (
                "Hashes",
                self.hashes,
                "Pod UIDs, container IDs, volume names, checksums",
            ),
            (
                "UUIDs",
                self.uuids,
                "Request IDs, trace IDs, unique identifiers",
            ),
            (
                "Durations",
                self.durations,
                "Timeouts, latencies, elapsed times",
            ),
            (
                "Process IDs",
                self.pids,
                "PIDs, thread IDs, process identifiers",
            ),
            (
                "File Sizes",
                self.sizes,
                "Memory usage, file sizes, data volumes",
            ),
            (
                "Numbers/Percentages",
                self.percentages,
                "CPU usage, percentages, metrics",
            ),
            (
                "HTTP Status",
                self.http_status,
                "Response codes, error codes",
            ),
            ("File Paths", self.paths, "File paths, URLs, directories"),
            ("JSON", self.json, "Inline JSON objects"),
            (
                "Quoted Strings",
                self.quoted_strings,
                "Quoted values and messages",
            ),
            ("Names", self.names, "Hyphenated component names"),
            (
                "Bracket Contexts",
                self.brackets,
                "[error] [module] logging contexts",
            ),
            (
                "Key-Value Pairs",
                self.key_values,
                "key=value configuration and metrics",
            ),
            (
                "Log Modules",
                self.log_modules,
                "[level] module logging patterns",
            ),
            (
                "Structured Messages",
                self.structured,
                "JSON/logfmt structured log envelopes",
            ),
            (
                "Kubernetes",
                self.kubernetes,
                "Namespaces, volumes, plugins, pod names",
            ),
            (
                "Email Addresses",
                self.emails,
                "RFC 5322 email addresses, user accounts",
            ),
        ]
    }

    fn pattern_hits(&self) -> PatternHits {
        PatternHits {
            timestamps: self.timestamps,
            ips: self.ips,
            ports: self.ports,
            fqdns: self.fqdns,
            hashes: self.hashes,
            uuids: self.uuids,
            pids: self.pids,
            durations: self.durations,
            http_status: self.http_status,
            sizes: self.sizes,
            percentages: self.percentages,
            paths: self.paths,
            json: self.json,
            quoted_strings: self.quoted_strings,
            names: self.names,
            brackets: self.brackets,
            key_values: self.key_values,
            log_modules: self.log_modules,
            structured: self.structured,
            kubernetes: self.kubernetes,
            emails: self.emails,
        }
    }
}

#[derive(Serialize)]
struct StatsJson {
    input_lines: usize,
    output_lines: usize,
    compression_ratio: f64,
    collapsed_groups: usize,
    lines_saved: usize,
    patterns_detected: usize,
    elapsed_ms: u64,
    pattern_hits: PatternHits,
}

#[derive(Serialize)]
struct PatternHits {
    timestamps: usize,
    ips: usize,
    ports: usize,
    fqdns: usize,
    hashes: usize,
    uuids: usize,
    pids: usize,
    durations: usize,
    http_status: usize,
    sizes: usize,
    percentages: usize,
    paths: usize,
    json: usize,
    quoted_strings: usize,
    names: usize,
    brackets: usize,
    key_values: usize,
    log_modules: usize,
    structured: usize,
    kubernetes: usize,
    emails: usize,
}

// -------------------------------------------------------------------------
// --preflight JSON schema. One pretty-printed report to stdout instead of
// fold output; consumed by automation/CI.
// -------------------------------------------------------------------------

#[derive(Serialize)]
struct PreflightReport {
    total_lines: usize,
    estimated_compression: CompressionEstimates,
    pattern_distribution: PatternDistribution,
    recommendations: Vec<String>,
    sample_patterns: SamplePatterns,
}

/// Since the per-scenario compression simulation was removed (it was dead
/// code), all four fields carry the same measured value. They are kept so
/// the --preflight JSON schema stays stable for existing consumers.
#[derive(Serialize)]
struct CompressionEstimates {
    default: String,
    with_paths: String,
    with_numbers: String,
    aggressive: String,
}

#[derive(Serialize)]
struct PatternDistribution {
    timestamps: usize,
    ips: usize,
    paths: usize,
    hashes: usize,
    numbers: usize,
    uuids: usize,
    pids: usize,
}

#[derive(Serialize)]
struct SamplePatterns {
    paths: Vec<String>,
    numbers: Vec<String>,
    timestamps: Vec<String>,
    ips: Vec<String>,
}

// -------------------------------------------------------------------------
// JSONL output schema (Phase 2 — no rollups yet).
//
// One `GroupRecord` per flushed PatternGroup is emitted to stdout. After the
// main loop, exactly one `SummaryRecord` terminates the stream. The `type`
// field discriminates the two. The schema is documented in docs/format-json-schema.md.
//
// Phase 3 will add a `variation` field to `GroupRecord`. Phase 2 leaves room
// for it but does not emit it.
// -------------------------------------------------------------------------

/// A reference to a line of the original input. `line_no` is the exact
/// 1-indexed position within `source`, or within stdin when `source` is null.
#[derive(Serialize)]
struct LineRef {
    /// Explicit input filename, or null when the line came from stdin.
    source: Option<String>,
    line: String,
    line_no: usize,
}

/// Raw timestamp strings observed in the first and last lines of the group.
/// Both fields may be null if the corresponding line had no detected
/// timestamp token. Strings are compared as raw input order (no parsing).
#[derive(Serialize)]
struct TimeRange {
    first_seen: Option<String>,
    last_seen: Option<String>,
}

/// One folded-group record in the JSONL stream.
#[derive(Serialize)]
struct GroupRecord {
    #[serde(rename = "type")]
    record_type: &'static str, // always "group"
    id: usize,
    count: usize,
    /// Sorted list of token type discriminant names present in the group's
    /// first or last line. Deterministic across runs.
    token_types: Vec<&'static str>,
    /// The first line's normalized form (with `<TOKEN>` placeholders).
    normalized: String,
    first: LineRef,
    last: LineRef,
    time_range: TimeRange,
    /// Per-token-type variation metadata (Phase 3): distinct counts plus
    /// deterministic samples for sample-worthy types. The key order is
    /// stable (BTreeMap) so agents can diff records across runs.
    variation: GroupRollup,
}

/// Terminal summary record for the JSONL stream. Flattens the existing
/// `StatsJson` fields and adds a `type: "summary"` discriminant so JSONL
/// consumers can branch cleanly on the record type.
#[derive(Serialize)]
struct SummaryRecord {
    #[serde(rename = "type")]
    record_type: &'static str, // always "summary"
    #[serde(flatten)]
    stats: StatsJson,
    completeness: Completeness,
}

#[derive(Serialize, Default)]
struct Completeness {
    complete: bool,
    input: InputCompleteness,
    groups: GroupCompleteness,
    variation_values: VariationCompleteness,
}

#[derive(Serialize, Default)]
struct InputCompleteness {
    complete: bool,
    processed_lines: usize,
    skipped_overlong_lines: Count,
    unprocessed_after_max_lines: Count,
    failed_sources: Count,
}

#[derive(Serialize, Default)]
struct GroupCompleteness {
    complete: bool,
    emitted: usize,
    total: Count,
    omitted_by_top: Count,
    omitted_by_summary_cap: Count,
    omitted_by_fit: Count,
}

#[derive(Serialize, Default)]
struct VariationCompleteness {
    complete: bool,
    capped_entries: usize,
    sampled_entries: usize,
    uncomputed_groups: usize,
    omitted_values: Count,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
struct Count {
    value: Option<usize>,
    kind: &'static str,
}

impl Default for Count {
    fn default() -> Self {
        Self::exact(0)
    }
}

impl Count {
    const fn exact(value: usize) -> Self {
        Self {
            value: Some(value),
            kind: "exact",
        }
    }

    const fn lower_bound(value: usize) -> Self {
        Self {
            value: Some(value),
            kind: "lower_bound",
        }
    }

    const fn unknown() -> Self {
        Self {
            value: None,
            kind: "unknown",
        }
    }
}

/// Discriminant name for a Token, used in `GroupRecord.token_types` and
/// (in Phase 3) as the key in the `variation` map. Stable across
/// serialisation runs because each variant returns a `&'static str`.
fn token_type_name(token: &Token) -> &'static str {
    match token {
        Token::Timestamp(_) => "TIMESTAMP",
        Token::IPv4(_) => "IPV4",
        Token::IPv6(_) => "IPV6",
        Token::Fqdn(_) => "FQDN",
        Token::Port(_) => "PORT",
        Token::Hash(_, _) => "HASH",
        Token::Uuid(_) => "UUID",
        Token::Pid(_) => "PID",
        Token::ThreadID(_) => "THREAD_ID",
        Token::Path(_) => "PATH",
        Token::Json(_) => "JSON",
        Token::Duration(_) => "DURATION",
        Token::Size(_) => "SIZE",
        Token::Number(_) => "NUMBER",
        Token::HttpStatus(_) => "HTTP_STATUS",
        Token::QuotedString(_) => "QUOTED_STRING",
        Token::Name(_) => "NAME",
        Token::KubernetesNamespace(_) => "K8S_NAMESPACE",
        Token::VolumeName(_) => "K8S_VOLUME",
        Token::PluginType(_) => "K8S_PLUGIN",
        Token::PodName(_) => "K8S_POD",
        Token::HttpStatusClass(_) => "HTTP_STATUS_CLASS",
        Token::BracketContext(_) => "BRACKET_CONTEXT",
        Token::KeyValuePair { .. } => "KEY_VALUE",
        Token::LogWithModule { .. } => "LOG_WITH_MODULE",
        Token::StructuredMessage { .. } => "STRUCTURED_MESSAGE",
        Token::Email(_) => "EMAIL",
    }
}

/// Extract the first `Token::Timestamp(s)` value from a slice, if any.
fn first_timestamp_in(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|t| match t {
        Token::Timestamp(s) => Some(s.clone()),
        _ => None,
    })
}

// -------------------------------------------------------------------------
// Rollup metadata.
//
// Per-group rollups capture what VARIES inside a folded group: for each
// token type that appeared in the group, the distinct-value count and a
// small deterministic sample of those values. Agents use this to answer
// triage questions without re-reading the raw log — "is this one UUID
// repeating or 1273 distinct UUIDs?", "which paths were affected?", etc.
//
// See .ideas/structured-folding-output-for-agents.md for design rationale
// and docs/rollup-calibration.md for the evidence behind the constants
// below.
// -------------------------------------------------------------------------

/// K: maximum number of samples surfaced per token type in JSON mode.
///
/// Calibrated via `cargo bench --bench calibrate_rollup` as the P95 of
/// observed distinct_count on sample-worthy token types across the full
/// corpus, capped at 8 (terminal-width ceiling). P95 on the corpus was
/// 7, so K=7 captures the COMPLETE distinct set for 95% of groups with
/// nothing hidden.
const ROLLUP_K: usize = 7;

/// Maximum distinct values tracked per (group, token type).
///
/// Calibrated as the smallest power-of-two ≥ P99 of observed
/// distinct_count on sample-worthy types. P99 was 35, so the next
/// power-of-two (64) covers 99% of groups exactly; the remaining 1%
/// trigger the `capped` flag (useful signal to the agent: "≥64 and
/// possibly many more"). 64 is small enough to keep per-group memory
/// bounded even at flush time.
pub const ROLLUP_DISTINCT_CAP: usize = 64;

/// Text-mode inline-sample threshold: when `distinct_count <=` this
/// value, the compact marker shows the complete distinct set; otherwise
/// count-only.
///
/// Calibrated via direct measurement of rendered marker lengths on the
/// corpus. Even at T=3, some markers exceed 120 chars due to long URL
/// paths inside samples — mitigated by truncating individual sample
/// values to 50 chars with a `…` suffix inside `render_compact_marker`.
/// Higher thresholds did not improve the pass rate meaningfully.
const ROLLUP_TEXT_SAMPLE_THRESHOLD: usize = 3;

/// One entry in the variation map: count, samples (possibly truncated),
/// and `capped` flag indicating whether the cap was hit.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(into = "JsonVariationEntry")]
struct VariationEntry {
    pub distinct_count: usize,
    pub samples: Vec<String>,
    pub capped: bool,
}

#[derive(Serialize)]
struct JsonVariationEntry {
    distinct_count: usize,
    distinct_count_kind: &'static str,
    samples: Vec<String>,
    capped: bool,
    samples_complete: bool,
    omitted_sample_values: Count,
}

impl From<VariationEntry> for JsonVariationEntry {
    fn from(entry: VariationEntry) -> Self {
        let omitted = entry.distinct_count.saturating_sub(entry.samples.len());
        Self {
            distinct_count: entry.distinct_count,
            distinct_count_kind: if entry.capped { "lower_bound" } else { "exact" },
            samples_complete: !entry.capped && omitted == 0,
            omitted_sample_values: if entry.capped {
                Count::lower_bound(omitted)
            } else {
                Count::exact(omitted)
            },
            samples: entry.samples,
            capped: entry.capped,
        }
    }
}

/// Full rollup for a single group — a sorted map from token type name to
/// its variation entry. BTreeMap gives deterministic iteration order,
/// which flows through to the JSON field order.
type GroupRollup = BTreeMap<&'static str, VariationEntry>;

/// Is this token type worth surfacing as samples (i.e., does the value
/// carry identity information useful to an agent)?
///
/// - **Sample-worthy** (identity types): UUID, IP, Path, Email, Hash,
///   Kubernetes objects, HTTP status, quoted strings, names, bracket
///   context, structured JSON — values an agent uses to identify which
///   specific entities were involved.
/// - **Count-only** (measurement types): Timestamp, Port, Pid, ThreadID,
///   Duration, Size, Number, KeyValuePair, LogWithModule,
///   StructuredMessage — values where "how many distinct" is useful but
///   showing specific values is noise.
///
/// The Phase 5 calibration may move token types between categories based
/// on observed real-world value-to-noise ratio.
fn is_sample_worthy(token: &Token) -> bool {
    matches!(
        token,
        Token::Uuid(_)
            | Token::IPv4(_)
            | Token::IPv6(_)
            | Token::Fqdn(_)
            | Token::Path(_)
            | Token::Email(_)
            | Token::Hash(_, _)
            | Token::KubernetesNamespace(_)
            | Token::VolumeName(_)
            | Token::PluginType(_)
            | Token::PodName(_)
            | Token::QuotedString(_)
            | Token::Name(_)
            | Token::HttpStatus(_)
            | Token::HttpStatusClass(_)
            | Token::BracketContext(_)
            | Token::Json(_)
    )
}

/// Extract the string representation of a token for sampling.
/// Used only for sample-worthy token types; count-only types use
/// `hash_token_value` instead to avoid retaining large strings.
fn token_value_string(token: &Token) -> String {
    match token {
        Token::Timestamp(s)
        | Token::IPv4(s)
        | Token::IPv6(s)
        | Token::Fqdn(s)
        | Token::Uuid(s)
        | Token::Path(s)
        | Token::Json(s)
        | Token::Duration(s)
        | Token::Size(s)
        | Token::Number(s)
        | Token::QuotedString(s)
        | Token::Name(s)
        | Token::KubernetesNamespace(s)
        | Token::VolumeName(s)
        | Token::PluginType(s)
        | Token::PodName(s)
        | Token::ThreadID(s)
        | Token::HttpStatusClass(s)
        | Token::Email(s) => s.clone(),
        Token::Hash(_, s) => s.clone(),
        Token::BracketContext(parts) => parts.join(","),
        Token::Port(p) => p.to_string(),
        Token::HttpStatus(s) => s.to_string(),
        Token::Pid(p) => p.to_string(),
        Token::KeyValuePair { key, value_type } => format!("{key}={value_type}"),
        Token::LogWithModule { level, module } => format!("{level}:{module}"),
        Token::StructuredMessage { component, level } => format!("{component}:{level}"),
    }
}

/// Hash a token value to a u64. Used for count-only tracking of
/// high-cardinality types (Timestamp, Number, Duration, ...) where
/// retaining full strings would blow the memory budget.
///
/// Uses the same FNV-1a hashing as `seed_for_group` — NOT
/// `ahash::AHasher::default()` — so `distinct_count` is deterministic
/// across processes. For count-only types this mostly matters when the
/// distinct_cap is hit: the specific set of tracked hashes would
/// otherwise depend on per-process randomness, which in turn could
/// shift `distinct_count` by one on cap boundaries. Keeping everything
/// fixed-seed sidesteps that class of flake entirely.
fn hash_token_value(token: &Token) -> u64 {
    // Reuse `token_value_string` to get a canonical string representation,
    // then run FNV-1a over its bytes. This is slower than hashing field
    // bytes directly but keeps the code in one place. Count-only tokens
    // are rare per line compared to the total workload, so the overhead
    // is negligible relative to pattern detection.
    let canonical = token_value_string(token);
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    for b in canonical.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Seed for the deterministic sample RNG. Derived from the group's
/// normalized template so the same template → the same seed → the same
/// sample draw. This is the non-negotiable determinism contract.
///
/// Uses FNV-1a — NOT `ahash::AHasher::default()`, which seeds randomly
/// per process and breaks determinism across runs. FNV-1a is trivially
/// cross-platform and cross-version stable. Quality is sufficient for
/// seeding a ChaCha8Rng; we're not defending a hash table.
fn seed_for_group(normalized: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    for b in normalized.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Render the text-mode compact marker for a collapsed group, using
/// the rollup metadata computed at flush time.
///
/// Output shape:
///   `[+N similar | first_ts → last_ts | TYPE×count {s1, s2}, TYPE×count]`
///
/// - The word `similar` is kept for backwards compatibility with the
///   existing test suite (many tests grep for it).
/// - The time-range segment is only included when both `first_ts` and
///   `last_ts` are present (they come from the first `Token::Timestamp`
///   in the respective line's tokens). In essence mode, timestamps are
///   omitted even when present.
/// - Variation entries render with samples inline when
///   `distinct_count <= inline_threshold` and the entry is not capped,
///   else count-only (with a trailing `+` for capped entries).
/// - If the rollup is empty (either because the group was too small to
///   compute, or because none of its token types varied), falls back to
///   the minimal `[+N similar]` form. This keeps text output coherent
///   when the Phase 3 min_collapse guard skips rollup computation.
fn render_compact_marker(
    count: usize,
    rollup: &GroupRollup,
    first_ts: Option<&str>,
    last_ts: Option<&str>,
    inline_threshold: usize,
    essence_mode: bool,
) -> String {
    let mut out = format!("[+{count} similar");

    // Time range segment. Keep raw strings — the plan deliberately
    // avoided timestamp parsing (see design doc §Why flush-time).
    if !essence_mode && let (Some(a), Some(b)) = (first_ts, last_ts) {
        out.push_str(" | ");
        out.push_str(a);
        out.push_str(" → ");
        out.push_str(b);
    }

    // Variation segment. Skip count-only types from the inline render —
    // "TIMESTAMP×1000" noise would dominate the marker with no
    // information payoff. Sample-worthy types always get rendered.
    let worthy: Vec<(&&'static str, &VariationEntry)> = rollup
        .iter()
        .filter(|(_, entry)| !entry.samples.is_empty() || entry.distinct_count <= inline_threshold)
        .filter(|(_, entry)| entry.distinct_count > 0)
        .collect();

    if !worthy.is_empty() {
        // Per-sample truncation length. Calibration (Phase 5) showed
        // that un-truncated samples blow text markers to 1000+ chars on
        // logs with URL-heavy paths, because a 200-char URL multiplied
        // by three inlined samples dominates the line. 50 chars is
        // enough to convey the shape of the value (/var/lib/pods/...,
        // https://api.example.com/...) without exploding the marker.
        const SAMPLE_MAX_LEN: usize = 50;
        fn truncate_sample(s: &str) -> String {
            if s.len() <= SAMPLE_MAX_LEN {
                s.to_string()
            } else {
                let mut out = s.chars().take(SAMPLE_MAX_LEN - 1).collect::<String>();
                out.push('…');
                out
            }
        }

        out.push_str(" | ");
        let mut first = true;
        for (name, entry) in &worthy {
            if !first {
                out.push_str(", ");
            }
            first = false;
            // Text-mode convention is lowercase token type names (matches
            // the existing `summarize_variation_types` output in
            // `normalize.rs` that integration tests assert against).
            // JSON mode keeps UPPERCASE keys in the `variation` map
            // — the two conventions are deliberately different.
            out.push_str(&name.to_lowercase());
            out.push('×');
            out.push_str(&entry.distinct_count.to_string());
            if entry.capped {
                out.push('+');
            }
            // Inline samples when the full distinct set fits.
            if entry.distinct_count <= inline_threshold
                && !entry.capped
                && !entry.samples.is_empty()
            {
                out.push_str(" {");
                let truncated: Vec<String> =
                    entry.samples.iter().map(|s| truncate_sample(s)).collect();
                out.push_str(&truncated.join(", "));
                out.push('}');
            }
        }
    }

    out.push(']');
    out
}

/// Intermediate accumulator for one (group, token_type) pair during
/// rollup computation. Sample-worthy types retain strings; count-only
/// types retain u64 hashes. Both cap at `distinct_cap`.
enum Accumulator {
    /// Sample-worthy: retain full values so we can draw samples.
    Values(HashSet<String>),
    /// Count-only: retain only hashes so memory stays bounded.
    Hashes(HashSet<u64>),
}

impl Accumulator {
    fn len(&self) -> usize {
        match self {
            Self::Values(s) => s.len(),
            Self::Hashes(s) => s.len(),
        }
    }
}

/// Stateless rollup computer. One per `PatternFolder`. Parameters
/// (K, distinct_cap) are supplied by the constructor, defaulting to
/// the calibrated `ROLLUP_*` constants via `with_defaults`.
struct RollupComputer {
    k: usize,
    distinct_cap: usize,
}

impl RollupComputer {
    fn new(k: usize, distinct_cap: usize) -> Self {
        Self { k, distinct_cap }
    }

    fn with_defaults() -> Self {
        Self::new(ROLLUP_K, ROLLUP_DISTINCT_CAP)
    }

    /// Compute the rollup for one group. Iterates the group's lines
    /// once, bucketing each token into its per-type accumulator, then
    /// draws the final samples and produces one VariationEntry per
    /// token type that appeared.
    ///
    /// Complexity: O(total_tokens_in_group). Memory bound:
    /// `sum(min(distinct, cap)) × per-entry-size`, where per-entry-size
    /// is `sizeof(u64)` for count-only and `value_len` for sample-worthy.
    fn compute(&self, group: &PatternGroup) -> GroupRollup {
        // Flags + accumulators, keyed by token type name.
        // Kept as BTreeMap so the final JSON serialisation is sorted.
        let mut per_type: BTreeMap<&'static str, (Accumulator, bool)> = BTreeMap::new();

        // Upper bound on distinct values per token type: can't exceed
        // the number of lines in the group. Pre-allocating HashSets
        // with this hint avoids the grow-rehash cycle that shows up
        // disproportionately in parallel-mode flush timing.
        let capacity_hint = group.lines.len().min(self.distinct_cap);

        for line in &group.lines {
            for token in &line.tokens {
                let name = token_type_name(token);
                let sample_worthy = is_sample_worthy(token);

                let entry = per_type.entry(name).or_insert_with(|| {
                    (
                        if sample_worthy {
                            Accumulator::Values(HashSet::with_capacity(capacity_hint))
                        } else {
                            Accumulator::Hashes(HashSet::with_capacity(capacity_hint))
                        },
                        false, // capped flag
                    )
                });

                // Skip the insert if already capped — keeps cost bounded
                // and prevents per-insert growth beyond the cap.
                if entry.1 {
                    continue;
                }

                match &mut entry.0 {
                    Accumulator::Values(s) => {
                        if s.len() >= self.distinct_cap {
                            entry.1 = true;
                        } else {
                            s.insert(token_value_string(token));
                        }
                    }
                    Accumulator::Hashes(s) => {
                        if s.len() >= self.distinct_cap {
                            entry.1 = true;
                        } else {
                            s.insert(hash_token_value(token));
                        }
                    }
                }
            }
        }

        // Finalise: draw samples deterministically from each Accumulator.
        // Seed is per-group so same template → same draw.
        let mut rng = ChaCha8Rng::seed_from_u64(seed_for_group(&group.first().normalized));
        let mut out: GroupRollup = BTreeMap::new();
        for (name, (acc, capped)) in per_type {
            let distinct_count = acc.len();
            let samples = match acc {
                Accumulator::Values(s) => {
                    // Collect distinct values into a Vec, then let
                    // SliceRandom draw K uniformly. The HashSet's
                    // iteration order is unreliable across allocator
                    // versions; the intermediate Vec must therefore be
                    // sorted before sampling so the per-group seed ↔
                    // same sample draw invariant holds across hash
                    // seeds. This is load-bearing for determinism.
                    let mut distinct: Vec<String> = s.into_iter().collect();
                    distinct.sort();
                    let drawn_refs: Vec<&String> =
                        distinct.choose_multiple(&mut rng, self.k).collect();
                    let mut drawn: Vec<String> = drawn_refs.into_iter().cloned().collect();
                    // Sort the drawn sample itself for a stable JSON
                    // representation regardless of draw order.
                    drawn.sort();
                    drawn
                }
                Accumulator::Hashes(_) => Vec::new(),
            };
            out.insert(
                name,
                VariationEntry {
                    distinct_count,
                    samples,
                    capped,
                },
            );
        }
        out
    }
}

impl PatternFolder {
    pub fn new(config: Config) -> Self {
        let normalizer = Normalizer::new(config.clone());
        let thread_pool = match config.thread_count {
            Some(requested) if requested > 1 => {
                // A raw N-thread pool for arbitrary N is a footgun: --threads
                // 999999 would spawn ~1M OS threads and take the machine down.
                // More threads than cores never helps this CPU-bound pipeline.
                let cores = std::thread::available_parallelism().map_or(8, usize::from);
                let n = requested.min(cores);
                if n < requested {
                    eprintln!(
                        "lessence: capping --threads {requested} at {n} (available parallelism)"
                    );
                }
                match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
                    Ok(pool) => Some(pool),
                    Err(e) => {
                        eprintln!(
                            "lessence: could not create a {n}-thread pool ({e}); \
                             falling back to the default thread pool"
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        Self {
            config,
            normalizer,
            thread_pool,
            buffer: Vec::new(),
            group_index: ahash::AHashMap::new(),
            stats: FoldingStats::default(),
            position_counter: 0,
            batch_buffer: Vec::new(),
            batch_locations: Vec::new(),
            sources: Vec::new(),
            markdown_entries: Vec::new(),
            next_json_id: 0,
            json_input_complete: true,
            json_max_lines_reached: false,
            json_failed_sources: false,
            json_skipped_overlong_lines: 0,
            json_groups_emitted: 0,
            json_groups_total: None,
            json_omitted_by_top: 0,
            json_omitted_by_summary_cap: 0,
            json_omitted_by_fit: 0,
            json_capped_entries: 0,
            json_uncomputed_variation_groups: 0,
            json_sampled_entries: 0,
            json_omitted_values_lower_bound: 0,
            rollup_computer: RollupComputer::with_defaults(),
        }
    }

    /// Absorb the ingestion outcome for the completeness section of the
    /// JSONL summary record. One call after `Ingestor::run`, replacing the
    /// order-sensitive per-fact callbacks main used to invoke; the group
    /// and variation completeness fields are derived internally by the
    /// fold/finish paths. The fields set here are only read when the JSON
    /// summary record is rendered.
    pub fn absorb_ingest_report(&mut self, report: &IngestReport, any_source_failed: bool) {
        self.json_skipped_overlong_lines += report.overlong_lines_skipped;
        if report.max_lines_reached {
            self.json_input_complete = false;
            self.json_max_lines_reached = true;
        }
        if any_source_failed {
            self.json_input_complete = false;
            self.json_failed_sources = true;
        }
    }

    /// Register one explicit input filename and return a compact handle that
    /// can be attached to every line from that reader without cloning it.
    pub fn register_source(&mut self, source: String) -> SourceId {
        let id = u32::try_from(self.sources.len()).expect("too many input files");
        self.sources.push(source);
        SourceId(id)
    }

    fn source_name(&self, source_id: SourceId) -> Option<String> {
        if source_id == SourceId::STDIN {
            None
        } else {
            self.sources.get(source_id.0 as usize).cloned()
        }
    }

    /// Is the configured output format the JSON (JSONL) variant?
    fn is_json_output(&self) -> bool {
        matches!(self.config.output_format.as_str(), "json" | "jsonl")
    }

    /// Is the configured output format markdown?
    fn is_markdown_output(&self) -> bool {
        self.config.output_format.as_str() == "markdown"
    }

    pub fn process_line(&mut self, line: &str) -> Result<Option<String>> {
        self.process_line_impl(line, None)
    }

    /// Process a line with its exact source location. This is used by the
    /// JSON CLI path; text-mode callers keep using `process_line` and pay no
    /// provenance-tracking cost.
    pub fn process_line_at(
        &mut self,
        line: &str,
        source_id: Option<SourceId>,
        line_no: usize,
    ) -> Result<Option<String>> {
        let location = LineLocation::new(source_id.unwrap_or(SourceId::STDIN), line_no);
        self.process_line_impl(line, Some(location))
    }

    /// Shared body of `process_line` / `process_line_at`. `location` is the
    /// exact source position carried through to JSON output; `None` skips
    /// all provenance tracking (text-mode cost stays unchanged).
    fn process_line_impl(
        &mut self,
        line: &str,
        location: Option<LineLocation>,
    ) -> Result<Option<String>> {
        self.stats.total_lines += 1;
        self.position_counter += 1;

        // Parallel processing: batch lines for parallel pattern detection
        if self.config.thread_count != Some(1) {
            self.batch_buffer.push(line.to_string());
            if let Some(location) = location {
                self.batch_locations.push(location);
            }

            if self.batch_buffer.len() >= 10_000 {
                self.process_batch()?;
            }

            return Ok(None);
        }

        // Single-thread mode: sequential processing
        let normalized_line = self.normalizer.normalize_line(line.to_string())?;

        if !normalized_line.tokens.is_empty() {
            self.stats.patterns_detected += 1;
            self.count_pattern_types(&normalized_line.tokens);
        }

        // Try to find a matching group in the buffer
        self.cluster_line_at(normalized_line, location);

        // Smart flushing: flush groups that are old enough to be safe
        if self.should_flush_buffer() {
            return self.flush_oldest_safe_group();
        }

        Ok(None)
    }

    /// Attach a normalized line to its group: O(1) exact-hash lookup via
    /// `group_index` first, then the linear similarity scan, then a new
    /// group. The hash shortcut picks the same group the scan would (see
    /// the `group_index` field docs).
    fn cluster_line_at(&mut self, normalized_line: LogLine, location: Option<LineLocation>) {
        let match_index = if let Some(&idx) = self.group_index.get(&normalized_line.hash) {
            Some(idx)
        } else {
            self.buffer
                .iter()
                .position(|group| self.normalizer.are_similar(&normalized_line, group.first()))
        };

        if let Some(index) = match_index {
            if let Some(location) = location {
                self.buffer[index].add_line_at(normalized_line, location);
            } else {
                self.buffer[index].add_line(normalized_line, self.position_counter);
            }
        } else {
            // Create a new group at current position
            let rep_hash = normalized_line.hash;
            let group = if let Some(location) = location {
                PatternGroup::new_at(normalized_line, self.position_counter, location)
            } else {
                PatternGroup::new(normalized_line, self.position_counter)
            };
            self.buffer.push(group);
            let prev = self.group_index.insert(rep_hash, self.buffer.len() - 1);
            debug_assert!(prev.is_none(), "duplicate representative hash in buffer");
        }
    }

    fn flush_oldest_safe_group(&mut self) -> Result<Option<String>> {
        // Only flush groups that have been "untouched" for a while
        // This ensures we won't see new similar lines that could belong to them
        if self.buffer.is_empty() {
            return Ok(None);
        }

        // Find the oldest group that hasn't been updated recently
        let current_position = self.position_counter;
        let safe_distance = 100; // Lines since last update to consider "safe"

        let mut oldest_index = None;
        let mut oldest_position = usize::MAX;

        for (i, group) in self.buffer.iter().enumerate() {
            // A group is "safe" to flush if:
            // 1. It has enough lines to collapse OR it's far behind current position
            // 2. It's likely no more similar lines will come
            let is_old_enough = current_position - group.position > safe_distance;
            let is_ready = group.should_collapse(self.config.min_collapse) || is_old_enough;

            if is_ready && group.position < oldest_position {
                oldest_position = group.position;
                oldest_index = Some(i);
            }
        }

        if let Some(index) = oldest_index {
            let group = self.buffer.remove(index);
            // Keep the hash index in sync: drop the evicted group's entry
            // and shift every index past the removal point down by one.
            self.group_index.remove(&group.first().hash);
            for v in self.group_index.values_mut() {
                if *v > index {
                    *v -= 1;
                }
            }
            let formatted = self.format_group_dispatch(&group)?;
            // Track output lines: count newlines in formatted output + 1 for the last line
            self.stats.output_lines += formatted.lines().count();
            if self.is_markdown_output() {
                // Markdown assembles one document at the end of the run;
                // streamed evictions are buffered for it, not emitted.
                self.markdown_entries.push(formatted);
                return Ok(None);
            }
            // Every streamed eviction the caller receives in JSON mode is
            // one emitted group record (the caller writes it or dies before
            // the summary record that would report the count).
            if self.is_json_output() {
                self.json_groups_emitted += 1;
            }
            return Ok(Some(formatted));
        }

        Ok(None)
    }

    /// Prepare summary data: flush batches, merge groups by normalized text,
    /// sort by count descending, apply top-N / fit-budget / default cap.
    /// Returns (display_items, total_patterns, was_capped, fit_truncated).
    fn prepare_summary(
        &mut self,
        top_n: Option<usize>,
        fit_budget: Option<usize>,
    ) -> Result<(Vec<(usize, String)>, usize, bool, usize)> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        // Merge groups with the same normalized text (default mode keeps them
        // separate for chronological ordering, but summary wants global counts)
        let mut merged: HashMap<String, (usize, String)> = HashMap::new();
        for group in &self.buffer {
            let key = group.first().normalized.clone();
            let count = group.count();
            // The summary shows original lines, so --sanitize-pii masks
            // the representative here, before any renderer sees it.
            let representative = if self.config.sanitize_pii {
                apply_pii_masking(&group.first().original, &group.first().tokens)
            } else {
                group.first().original.clone()
            };
            merged
                .entry(key)
                .and_modify(|(c, _)| *c += count)
                .or_insert((count, representative));
        }

        // Sort by count descending; ties broken by the representative line
        // ascending so the order is deterministic across runs. Without this
        // secondary key, ahash's per-process HashMap iteration order
        // determines which tied entry wins the `--top N` cutoff, making the
        // visible summary differ between processes on the same input.
        let mut sorted: Vec<(usize, String)> = merged.into_values().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let total_patterns = sorted.len();
        const DEFAULT_SUMMARY_CAP: usize = 30;

        // Apply limit: explicit --top N, --fit budget, or default cap of 30
        let (display, was_capped, fit_truncated): (Vec<_>, bool, usize) = if let Some(0) = top_n {
            // --top 0 means show all (no limit, --fit still applies)
            if let Some(budget) = fit_budget {
                if sorted.len() > budget {
                    let show = budget.saturating_sub(1);
                    let remaining = sorted.len() - show;
                    (sorted.into_iter().take(show).collect(), false, remaining)
                } else {
                    (sorted, false, 0)
                }
            } else {
                (sorted, false, 0)
            }
        } else if let Some(n) = top_n {
            (sorted.into_iter().take(n).collect(), false, 0)
        } else if let Some(budget) = fit_budget {
            // --fit replaces the default cap with terminal height
            if sorted.len() > budget {
                let show = budget.saturating_sub(1);
                let remaining = sorted.len() - show;
                (sorted.into_iter().take(show).collect(), false, remaining)
            } else {
                (sorted, false, 0)
            }
        } else if total_patterns > DEFAULT_SUMMARY_CAP {
            (
                sorted.into_iter().take(DEFAULT_SUMMARY_CAP).collect(),
                true,
                0,
            )
        } else {
            (sorted, false, 0)
        };

        Ok((display, total_patterns, was_capped, fit_truncated))
    }

    pub fn finish(&mut self) -> Result<Vec<String>> {
        // Constitutional compliance: Process any remaining batch
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        let mut output = Vec::new();

        // Sort groups by position to maintain chronological order. The
        // buffer is emptied below, so the hash index goes with it.
        self.group_index.clear();
        self.buffer.sort_by_key(|group| group.position);

        // Flush all remaining groups in chronological order. take() empties
        // the buffer in O(1); the old remove(0) loop shifted the whole
        // vector on every iteration (O(n²) in buffered groups).
        for group in std::mem::take(&mut self.buffer) {
            let formatted = self.format_group_dispatch(&group)?;
            // Track output lines: count newlines in formatted output + 1 for the last line
            self.stats.output_lines += formatted.lines().count();
            if self.is_markdown_output() {
                self.markdown_entries.push(formatted);
            } else {
                output.push(formatted);
            }
        }
        // Same contract as the streamed path: everything returned in JSON
        // mode is one group record each.
        if self.is_json_output() {
            self.json_groups_emitted += output.len();
        }

        Ok(output)
    }

    /// Finish processing and return the top N groups by frequency, already
    /// cut down to the `--fit` budget. Returns the (count, formatted_output)
    /// pairs to show sorted by count descending, the total group count, the
    /// percentage of input lines the top N cover, and how many of the top N
    /// the fit budget dropped.
    ///
    /// `cap_is_summary` classifies the omitted groups for the JSON
    /// completeness record: true when the cap came from summary-mode's
    /// default (--summary --format json without an explicit --top), false
    /// for an explicit --top N.
    pub fn finish_top_n(
        &mut self,
        n: usize,
        fit_budget: Option<usize>,
        cap_is_summary: bool,
    ) -> Result<(Vec<(usize, String)>, usize, usize, usize)> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        // Groups already streamed out as JSON records before this ranking
        // pass count toward the total the summary record reports.
        let previously_formatted = self.next_json_id;

        // Collect all groups with their counts (drains the buffer, so the
        // hash index goes with it)
        self.group_index.clear();
        let mut groups_with_counts: Vec<(usize, PatternGroup)> =
            self.buffer.drain(..).map(|g| (g.count(), g)).collect();

        // Sort by count descending; ties broken by the group's normalized
        // representative ascending so the cutoff at `take(n)` is
        // deterministic across runs (otherwise ahash's per-process HashMap
        // iteration order shuffles tied entries past the cap).
        groups_with_counts.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.first().normalized.cmp(&b.1.first().normalized))
        });

        let total_groups = groups_with_counts.len();
        let total_input_lines = self.stats.total_lines;

        // Take top N
        let top_groups: Vec<(usize, PatternGroup)> =
            groups_with_counts.into_iter().take(n).collect();

        let lines_covered: usize = top_groups.iter().map(|(c, _)| c).sum();

        let mut output = Vec::new();
        for (count, group) in top_groups {
            let formatted = self.format_group_dispatch(&group)?;
            self.stats.output_lines += formatted.lines().count();
            output.push((count, formatted));
        }

        // Apply the --fit budget: keep budget-1 entries and report the rest
        // as truncated (the caller renders the "... N more" marker line).
        let fit_truncated = match fit_budget {
            Some(budget) if output.len() > budget => {
                let show = budget.saturating_sub(1);
                let truncated = output.len() - show;
                output.truncate(show);
                truncated
            }
            _ => 0,
        };

        // Derive the group-completeness facts for the JSON summary record
        // from what this ranking pass actually did.
        if self.is_json_output() {
            let all_groups = total_groups + previously_formatted;
            let omitted_before_fit = all_groups.saturating_sub(output.len() + fit_truncated);
            self.json_groups_emitted += output.len();
            self.json_groups_total = Some(all_groups);
            if cap_is_summary {
                self.json_omitted_by_summary_cap += omitted_before_fit;
            } else {
                self.json_omitted_by_top += omitted_before_fit;
            }
            self.json_omitted_by_fit += fit_truncated;
        }

        Ok((
            output,
            total_groups,
            if total_input_lines > 0 {
                (lines_covered as f64 / total_input_lines as f64 * 100.0) as usize
            } else {
                0
            },
            fit_truncated,
        ))
    }

    /// Determine if buffer should be flushed based on memory management
    fn should_flush_buffer(&self) -> bool {
        // Ranked modes (--summary, --fit, --top) rank the complete group set
        // after the run and never consume streamed evictions — evicting here
        // would silently drop groups from both the ranking and the coverage
        // denominator. Hold every group, exactly as the parallel pipeline
        // does for all modes.
        if self.config.summary || self.config.top_n.is_some() {
            return false;
        }
        // Constitutional flush threshold: Use dynamic memory management instead of arbitrary limits
        // This maintains pattern detection quality while following "complete files in memory" principle
        const CONSTITUTIONAL_FLUSH_THRESHOLD: usize = 1000;
        self.buffer.len() > CONSTITUTIONAL_FLUSH_THRESHOLD
    }

    fn count_pattern_types(&mut self, tokens: &[Token]) {
        for token in tokens {
            match token {
                Token::Timestamp(_) => self.stats.timestamps += 1,
                Token::IPv4(_) | Token::IPv6(_) => self.stats.ips += 1,
                Token::Fqdn(_) => self.stats.fqdns += 1,
                Token::Port(_) => self.stats.ports += 1,
                Token::Hash(_, _) => self.stats.hashes += 1,
                Token::Uuid(_) => self.stats.uuids += 1,
                Token::Pid(_) | Token::ThreadID(_) => self.stats.pids += 1,
                Token::Duration(_) => self.stats.durations += 1,
                Token::Size(_) => self.stats.sizes += 1,
                Token::Number(_) => self.stats.percentages += 1, // Numbers often include percentages
                Token::HttpStatus(_) | Token::HttpStatusClass(_) => self.stats.http_status += 1,
                Token::Path(_) => self.stats.paths += 1,
                Token::Json(_) => self.stats.json += 1,
                Token::QuotedString(_) => self.stats.quoted_strings += 1,
                Token::Name(_) => self.stats.names += 1,
                Token::KubernetesNamespace(_)
                | Token::VolumeName(_)
                | Token::PluginType(_)
                | Token::PodName(_) => self.stats.kubernetes += 1,
                Token::BracketContext(_) => self.stats.brackets += 1,
                Token::KeyValuePair { .. } => self.stats.key_values += 1,
                Token::LogWithModule { .. } => self.stats.log_modules += 1,
                Token::StructuredMessage { .. } => self.stats.structured += 1,
                Token::Email(_) => self.stats.emails += 1,
            }
        }
    }

    fn count_active_pattern_types(&self) -> usize {
        self.stats
            .pattern_counters()
            .iter()
            .filter(|(_, count, _)| *count > 0)
            .count()
    }

    /// Parallel batch processing: normalize in parallel, cluster sequentially
    fn process_batch(&mut self) -> Result<()> {
        let batch = std::mem::take(&mut self.batch_buffer);
        let locations = std::mem::take(&mut self.batch_locations);
        debug_assert!(locations.is_empty() || locations.len() == batch.len());
        let processed_lines = self.parallel_pattern_detection(&batch)?;

        for (index, processed_line) in processed_lines.into_iter().enumerate() {
            self.sequential_clustering_at(processed_line, locations.get(index).copied())?;
        }
        Ok(())
    }

    /// Phase 1: Parallel pattern detection and normalization (the CPU-intensive work)
    fn parallel_pattern_detection(&self, lines: &[String]) -> Result<Vec<LogLine>> {
        use rayon::prelude::*;

        // This is where the real CPU work happens - parallel regex pattern detection
        let detect = || {
            lines
                .par_iter()
                .map(|line| {
                    // CPU-intensive pattern detection - perfectly parallelizable
                    self.normalizer.normalize_line(line.clone())
                })
                .collect::<Result<Vec<_>, _>>()
        };
        // --threads N sizes a dedicated pool; otherwise rayon's global
        // default pool (auto-detected CPU count) does the work.
        let processed_lines: Vec<LogLine> = match &self.thread_pool {
            Some(pool) => pool.install(detect)?,
            None => detect()?,
        };

        Ok(processed_lines)
    }

    /// Phase 2: Fast sequential clustering using pre-computed normalized lines
    #[cfg(test)]
    fn sequential_clustering(&mut self, normalized_line: LogLine) -> Result<()> {
        self.sequential_clustering_at(normalized_line, None)
    }

    fn sequential_clustering_at(
        &mut self,
        normalized_line: LogLine,
        location: Option<LineLocation>,
    ) -> Result<()> {
        // Fast clustering using pre-computed patterns and hashes
        if !normalized_line.tokens.is_empty() {
            self.stats.patterns_detected += 1;
            self.count_pattern_types(&normalized_line.tokens);
        }

        // Fast similarity matching using pre-computed normalized text. The
        // grouping position remains batch-granular to preserve clustering and
        // flush behavior; `location` independently carries the exact source
        // position used by JSON output.
        self.cluster_line_at(normalized_line, location);

        Ok(())
    }

    /// Sequential processing for constitutional compliance (used internally)
    /// Get current statistics (for preflight analysis)
    pub fn get_stats(&self) -> &FoldingStats {
        &self.stats
    }
}

mod render;

#[cfg(test)]
mod tests;
