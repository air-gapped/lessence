use anyhow::Result;
use chrono::Utc;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::time::Duration;

use crate::config::Config;
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
            // Find all occurrences of this email in original text
            let mut start = 0;
            while let Some(pos) = result[start..].find(email) {
                let abs_pos = start + pos;
                email_ranges.push((abs_pos, abs_pos + email.len()));
                start = abs_pos + email.len();
            }
        }
    }

    // Sort ranges in reverse order (replace from end to preserve indices)
    email_ranges.sort_by(|a, b| b.0.cmp(&a.0));

    // Replace each email with <EMAIL> token
    for (start, end) in email_ranges {
        result.replace_range(start..end, "<EMAIL>");
    }

    result
}

#[derive(Debug)]
struct PatternGroup {
    lines: Vec<LogLine>,
    #[allow(dead_code)]
    collapsed: bool,
    position: usize, // Position when first line was encountered
    /// Input line number of the first line in this group (1-indexed).
    /// Used by the JSON output path; ignored by text/markdown formatting.
    first_line_no: usize,
    /// Input line number of the most recently added line in this group.
    /// Updated on every add_line().
    last_line_no: usize,
}

impl PatternGroup {
    fn new(line: LogLine, position: usize) -> Self {
        Self {
            lines: vec![line],
            collapsed: false,
            position,
            first_line_no: position,
            last_line_no: position,
        }
    }

    fn add_line(&mut self, line: LogLine, line_no: usize) {
        self.lines.push(line);
        self.last_line_no = line_no;
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

pub struct PatternFolder {
    config: Config,
    normalizer: Normalizer,
    buffer: Vec<PatternGroup>,
    stats: FoldingStats,
    position_counter: usize,
    batch_buffer: Vec<String>,
    /// Monotonic counter for JSON group record `id` fields. Incremented
    /// exactly once per flushed group in JSON mode. Stays at 0 in text /
    /// markdown modes. Stable within a run.
    next_json_id: usize,
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
    // Pattern distribution counters
    pub timestamps: usize,
    pub ips: usize,
    pub hashes: usize,
    pub uuids: usize,
    pub pids: usize,
    pub durations: usize,
    pub http_status: usize,
    pub sizes: usize,
    pub percentages: usize,
    pub paths: usize,
    pub kubernetes: usize,
    pub emails: usize, // Track email pattern detections
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
    hashes: usize,
    uuids: usize,
    pids: usize,
    durations: usize,
    http_status: usize,
    sizes: usize,
    percentages: usize,
    paths: usize,
    kubernetes: usize,
    emails: usize,
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

/// A reference to a line of the original input. `line_no` is the 1-indexed
/// input position of the line. In parallel mode it is approximate
/// (batch-granular); in single-threaded mode it is exact.
#[derive(Serialize)]
struct LineRef {
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
}

/// Discriminant name for a Token, used in `GroupRecord.token_types` and
/// (in Phase 3) as the key in the `variation` map. Stable across
/// serialisation runs because each variant returns a `&'static str`.
fn token_type_name(token: &Token) -> &'static str {
    match token {
        Token::Timestamp(_) => "TIMESTAMP",
        Token::IPv4(_) => "IPV4",
        Token::IPv6(_) => "IPV6",
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
const ROLLUP_DISTINCT_CAP: usize = 64;

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
struct VariationEntry {
    pub distinct_count: usize,
    pub samples: Vec<String>,
    pub capped: bool,
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

        Self {
            config,
            normalizer,
            buffer: Vec::new(),
            stats: FoldingStats::default(),
            position_counter: 0,
            batch_buffer: Vec::new(),
            next_json_id: 0,
            rollup_computer: RollupComputer::with_defaults(),
        }
    }

    /// Is the configured output format the JSON (JSONL) variant?
    fn is_json_output(&self) -> bool {
        matches!(self.config.output_format.as_str(), "json" | "jsonl")
    }

    /// Format a group for the configured output mode.
    ///
    /// Rollup metadata is computed unconditionally here — regardless of
    /// output format — so that the perf gate applies uniformly to both
    /// text and JSON modes. This is the single insertion point for the
    /// feature's flush-time cost. Text mode (Phase 4) renders a richer
    /// compact marker from the rollup; JSON mode (Phase 3) serialises
    /// the rollup as the `variation` field.
    ///
    /// Groups smaller than `min_collapse` skip the rollup entirely —
    /// there's no useful variation summary to report for a group of one
    /// or two lines, and the allocation cost of building empty
    /// accumulators dominated flush-time overhead in parallel mode
    /// before this guard was added. The `variation` field in JSON mode
    /// remains present (as an empty `{}`) so the schema shape is
    /// unchanged; only the compute cost is skipped.
    fn format_group_dispatch(&mut self, group: &PatternGroup) -> Result<String> {
        let rollup = if group.count() >= self.config.min_collapse {
            self.rollup_computer.compute(group)
        } else {
            BTreeMap::new()
        };
        if self.is_json_output() {
            self.format_group_json(group, rollup)
        } else {
            self.format_group(group, &rollup)
        }
    }

    /// Serialise one group as a JSONL record. Returns a single JSON object
    /// string **without** a trailing newline — the caller's `writeln!`
    /// supplies it. This matches `format_group`'s text-mode contract so the
    /// main loop's output path works uniformly for both formats.
    ///
    /// `output_lines` is updated by the *caller* (same as `format_group`
    /// via `formatted.lines().count()`) so both formatting paths keep
    /// stats coherent with no double-counting.
    fn format_group_json(
        &mut self,
        group: &PatternGroup,
        variation: GroupRollup,
    ) -> Result<String> {
        let id = self.next_json_id;
        self.next_json_id += 1;

        // Keep `collapsed_groups` and `lines_saved` coherent with
        // --stats-json output in JSON mode: a group with >= min_collapse
        // lines counts as "collapsed" even though JSON mode always emits
        // one record per group regardless of size. Without this, summary
        // statistics would differ between text-mode and JSON-mode runs
        // of the same input.
        if group.count() >= self.config.min_collapse && !self.config.essence_mode {
            self.stats.collapsed_groups += 1;
            // All lines except the one emitted as the representative
            // are accounted for as "saved". Matches text-mode lines_saved
            // semantics as closely as the JSON schema permits.
            self.stats.lines_saved += group.count() - 1;
        }

        // Collect unique token type names from first and last lines.
        // BTreeSet gives us deterministic sorted output for free.
        let mut token_types: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();
        for t in &group.first().tokens {
            token_types.insert(token_type_name(t));
        }
        for t in &group.last().tokens {
            token_types.insert(token_type_name(t));
        }

        let record = GroupRecord {
            record_type: "group",
            id,
            count: group.count(),
            token_types: token_types.into_iter().collect(),
            normalized: group.first().normalized.clone(),
            first: LineRef {
                line: group.first().original.clone(),
                line_no: group.first_line_no,
            },
            last: LineRef {
                line: group.last().original.clone(),
                line_no: group.last_line_no,
            },
            time_range: TimeRange {
                first_seen: first_timestamp_in(&group.first().tokens),
                last_seen: first_timestamp_in(&group.last().tokens),
            },
            variation,
        };

        Ok(serde_json::to_string(&record)?)
    }

    /// Emit the terminal summary record for a JSONL stream. Called once,
    /// after the main loop and `finish()` have drained all groups.
    /// Writes to `writer` (stdout in the main binary path) and ends with
    /// a trailing newline so the JSONL stream terminates cleanly.
    pub fn print_summary_json(&self, writer: &mut impl io::Write, elapsed: Duration) -> Result<()> {
        let compression_ratio = if self.stats.total_lines > 0 {
            (self.stats.lines_saved as f64 / self.stats.total_lines as f64) * 100.0
        } else {
            0.0
        };
        let record = SummaryRecord {
            record_type: "summary",
            stats: StatsJson {
                input_lines: self.stats.total_lines,
                output_lines: self.stats.output_lines,
                compression_ratio,
                collapsed_groups: self.stats.collapsed_groups,
                lines_saved: self.stats.lines_saved,
                patterns_detected: self.stats.patterns_detected,
                elapsed_ms: elapsed.as_millis() as u64,
                pattern_hits: PatternHits {
                    timestamps: self.stats.timestamps,
                    ips: self.stats.ips,
                    hashes: self.stats.hashes,
                    uuids: self.stats.uuids,
                    pids: self.stats.pids,
                    durations: self.stats.durations,
                    http_status: self.stats.http_status,
                    sizes: self.stats.sizes,
                    percentages: self.stats.percentages,
                    paths: self.stats.paths,
                    kubernetes: self.stats.kubernetes,
                    emails: self.stats.emails,
                },
            },
        };
        serde_json::to_writer(&mut *writer, &record)?;
        writeln!(writer)?;
        Ok(())
    }

    pub fn process_line(&mut self, line: &str) -> Result<Option<String>> {
        self.stats.total_lines += 1;
        self.position_counter += 1;

        // Parallel processing: batch lines for parallel pattern detection
        if self.config.thread_count != Some(1) {
            self.batch_buffer.push(line.to_string());

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
        let mut match_index = None;
        for (i, group) in self.buffer.iter().enumerate() {
            if self.normalizer.are_similar(&normalized_line, group.first()) {
                match_index = Some(i);
                break;
            }
        }

        if let Some(index) = match_index {
            self.buffer[index].add_line(normalized_line, self.position_counter);
        } else {
            // Create a new group at current position
            self.buffer
                .push(PatternGroup::new(normalized_line, self.position_counter));
        }

        // Smart flushing: flush groups that are old enough to be safe
        if self.should_flush_buffer() {
            return self.flush_oldest_safe_group();
        }

        Ok(None)
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
            let formatted = self.format_group_dispatch(&group)?;
            // Track output lines: count newlines in formatted output + 1 for the last line
            self.stats.output_lines += formatted.lines().count();
            return Ok(Some(formatted));
        }

        Ok(None)
    }

    /// Finish processing and output a one-line-per-pattern summary sorted by frequency.
    /// Uses the parallel pipeline for normalization, then merges groups with identical
    /// normalized text and displays representative original lines.
    pub fn finish_summary(
        &mut self,
        top_n: Option<usize>,
        fit_budget: Option<usize>,
    ) -> Result<()> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        // Merge groups with the same normalized text (default mode keeps them
        // separate for chronological ordering, but summary wants global counts)
        let mut merged: HashMap<String, (usize, String)> = HashMap::new();
        for group in &self.buffer {
            let key = group.first().normalized.clone();
            let count = group.count();
            let representative = group.first().original.clone();
            merged
                .entry(key)
                .and_modify(|(c, _)| *c += count)
                .or_insert((count, representative));
        }

        // Sort by count descending
        let mut sorted: Vec<(usize, String)> = merged.into_values().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0));

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
        let shown_count = display.len();

        // Detect terminal width for summary truncation (unlimited when piped)
        use std::io::IsTerminal;
        let max_width: Option<usize> = if std::io::stdout().is_terminal() {
            terminal_size::terminal_size().map(|(w, _)| w.0 as usize)
        } else {
            None
        };

        // Output: one line per pattern with representative original line
        for (count, representative) in &display {
            let prefix = format!("[{count}x] ");
            match max_width {
                Some(width) if prefix.len() + representative.len() > width => {
                    let avail = width.saturating_sub(prefix.len() + 3); // 3 for "..."
                    if avail > 20 {
                        println!("{prefix}{}...", &representative[..avail]);
                    } else {
                        println!("{prefix}{representative}");
                    }
                }
                _ => println!("{prefix}{representative}"),
            }
        }

        if fit_truncated > 0 {
            println!("... {fit_truncated} more patterns (remove --fit for full output)");
        }

        // Coverage info on stderr
        let shown_lines: usize = display.iter().map(|(c, _)| c).sum();
        let coverage = if self.stats.total_lines > 0 {
            (shown_lines as f64 / self.stats.total_lines as f64) * 100.0
        } else {
            0.0
        };
        if was_capped {
            eprintln!(
                "({shown_count} of {total_patterns} patterns, {coverage:.0}% coverage — use --top N to adjust, or --top 0 for all)",
            );
        } else {
            eprintln!(
                "({shown_count} of {total_patterns} patterns, {shown_lines} of {} lines, {coverage:.0}% coverage)",
                self.stats.total_lines
            );
        }

        Ok(())
    }

    pub fn finish(&mut self) -> Result<Vec<String>> {
        // Constitutional compliance: Process any remaining batch
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        // Apply second similarity pass to catch similar lines with different patterns
        // self.apply_second_similarity_pass()?;

        let mut output = Vec::new();

        // Sort groups by position to maintain chronological order
        self.buffer.sort_by_key(|group| group.position);

        // Flush all remaining groups in chronological order
        while !self.buffer.is_empty() {
            let group = self.buffer.remove(0);
            let formatted = self.format_group_dispatch(&group)?;
            // Track output lines: count newlines in formatted output + 1 for the last line
            self.stats.output_lines += formatted.lines().count();
            output.push(formatted);
        }

        Ok(output)
    }

    /// Finish processing and return the top N groups by frequency.
    /// Returns (count, formatted_output) pairs sorted by count descending,
    /// plus (total_groups, total_lines_covered_by_shown).
    pub fn finish_top_n(&mut self, n: usize) -> Result<(Vec<(usize, String)>, usize, usize)> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        // Collect all groups with their counts
        let mut groups_with_counts: Vec<(usize, PatternGroup)> =
            self.buffer.drain(..).map(|g| (g.count(), g)).collect();

        // Sort by count descending
        groups_with_counts.sort_by(|a, b| b.0.cmp(&a.0));

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

        // Store total_input_lines for coverage calc
        Ok((
            output,
            total_groups,
            if total_input_lines > 0 {
                (lines_covered as f64 / total_input_lines as f64 * 100.0) as usize
            } else {
                0
            },
        ))
    }

    /// Determine if buffer should be flushed based on memory management
    fn should_flush_buffer(&self) -> bool {
        // Constitutional flush threshold: Use dynamic memory management instead of arbitrary limits
        // This maintains pattern detection quality while following "complete files in memory" principle
        const CONSTITUTIONAL_FLUSH_THRESHOLD: usize = 1000;
        self.buffer.len() > CONSTITUTIONAL_FLUSH_THRESHOLD
    }

    /// Apply second similarity pass to merge groups that are similar but have different patterns
    #[allow(dead_code)]
    fn apply_second_similarity_pass(&mut self) -> Result<()> {
        if self.buffer.len() <= 1 {
            return Ok(());
        }

        let mut merged_any = true;
        let mut iterations = 0;

        // Keep trying to merge until no more merges are possible
        while merged_any && iterations < 10 {
            // Prevent infinite loops
            merged_any = false;
            iterations += 1;

            // Compare all pairs of groups
            let mut i = 0;
            while i < self.buffer.len() {
                let mut j = i + 1;
                while j < self.buffer.len() {
                    // Get representatives from each group (safe: buffer entries always have lines)
                    let Some(group1_first) = self.buffer[i].lines.first() else {
                        j += 1;
                        continue;
                    };
                    let Some(group2_first) = self.buffer[j].lines.first() else {
                        j += 1;
                        continue;
                    };

                    // Skip if they already have identical normalized forms (should already be grouped)
                    if group1_first.normalized == group2_first.normalized {
                        j += 1;
                        continue;
                    }

                    // Check if they're similar enough to merge
                    let similarity = self.normalizer.similarity_score(group1_first, group2_first);
                    if similarity >= f64::from(self.config.threshold) {
                        // Merge group j into group i
                        let group_to_merge = self.buffer.remove(j);
                        let merged_last_line_no = group_to_merge.last_line_no;
                        for line in group_to_merge.lines {
                            self.buffer[i].add_line(line, merged_last_line_no);
                        }

                        merged_any = true;
                        // Don't increment j since we removed an element
                    } else {
                        j += 1;
                    }
                }
                i += 1;
            }
        }

        Ok(())
    }

    fn count_pattern_types(&mut self, tokens: &[Token]) {
        for token in tokens {
            match token {
                Token::Timestamp(_) => self.stats.timestamps += 1,
                Token::IPv4(_) | Token::IPv6(_) => self.stats.ips += 1,
                Token::Port(_) => self.stats.ips += 1, // Count ports with IPs
                Token::Hash(_, _) => self.stats.hashes += 1,
                Token::Uuid(_) => self.stats.uuids += 1,
                Token::Pid(_) | Token::ThreadID(_) => self.stats.pids += 1,
                Token::Duration(_) => self.stats.durations += 1,
                Token::Size(_) => self.stats.sizes += 1,
                Token::Number(_) => self.stats.percentages += 1, // Numbers often include percentages
                Token::HttpStatus(_) => self.stats.http_status += 1,
                Token::Path(_) => self.stats.paths += 1,
                Token::Json(_) => self.stats.paths += 1, // Group with paths for stats
                Token::QuotedString(_) => self.stats.percentages += 1, // Group with percentages for now
                Token::Name(_) => self.stats.percentages += 1, // Group with generic patterns
                Token::KubernetesNamespace(_)
                | Token::VolumeName(_)
                | Token::PluginType(_)
                | Token::PodName(_) => self.stats.kubernetes += 1,
                // New patterns from 001-read-the-current
                Token::HttpStatusClass(_) => self.stats.http_status += 1,
                Token::BracketContext(_) => self.stats.percentages += 1, // Group with generic patterns
                Token::KeyValuePair { .. } => self.stats.percentages += 1, // Group with generic patterns
                Token::LogWithModule { .. } => self.stats.percentages += 1, // Group with generic patterns
                Token::StructuredMessage { .. } => self.stats.percentages += 1, // Group with generic patterns
                Token::Email(_) => self.stats.emails += 1, // Track email patterns separately
            }
        }
    }

    fn format_group(&mut self, group: &PatternGroup, rollup: &GroupRollup) -> Result<String> {
        if group.should_collapse(self.config.min_collapse) && !self.config.essence_mode {
            self.stats.collapsed_groups += 1;
            self.stats.lines_saved += group.count() - 3; // First, summary, and last lines are output

            // Phase 4: when the rollup has any worthwhile content, render
            // the richer compact marker directly. Otherwise fall through
            // to the legacy `format_collapsed_line` path — this applies
            // to small groups whose rollup was skipped (see
            // `format_group_dispatch`), keeping behaviour unchanged for
            // that code path.
            let collapsed_line = if !rollup.is_empty() {
                let first_ts = first_timestamp_in(&group.first().tokens);
                let last_ts = first_timestamp_in(&group.last().tokens);
                render_compact_marker(
                    group.count() - 2,
                    rollup,
                    first_ts.as_deref(),
                    last_ts.as_deref(),
                    ROLLUP_TEXT_SAMPLE_THRESHOLD,
                    self.config.essence_mode,
                )
            } else {
                self.normalizer.format_collapsed_line(
                    group.first(),
                    group.last(),
                    group.count() - 2, // Don't count first and last in collapse count
                )
            };

            // Format output: first line, collapsed summary, last line
            let mut result = String::new();
            let first_line = if self.config.essence_mode {
                // Constitutional essence mode: use timestamp-removed text
                &group.first().normalized
            } else {
                // Standard mode: use original text (with optional PII masking)
                &group.first().original
            };

            // Apply PII masking if enabled
            let first_line_output = if self.config.sanitize_pii && !self.config.essence_mode {
                apply_pii_masking(first_line, &group.first().tokens)
            } else {
                first_line.clone()
            };
            result.push_str(&first_line_output);
            result.push('\n');
            result.push_str(&collapsed_line);

            // Only add last line if it's different from first
            if group.count() > 1 {
                let last_line = if self.config.essence_mode {
                    // Constitutional essence mode: use timestamp-removed text
                    &group.last().normalized
                } else {
                    // Standard mode: use original text (with optional PII masking)
                    &group.last().original
                };

                // In essence mode, only show last line if it's actually different from first
                // (after timestamp tokenization, truly similar lines should have identical normalized text)
                if !self.config.essence_mode || first_line != last_line {
                    result.push('\n');

                    // Apply PII masking if enabled
                    let last_line_output = if self.config.sanitize_pii && !self.config.essence_mode
                    {
                        apply_pii_masking(last_line, &group.last().tokens)
                    } else {
                        last_line.clone()
                    };
                    result.push_str(&last_line_output);
                }
            }

            Ok(result)
        } else {
            // Output lines individually
            let mut result = String::new();

            if self.config.essence_mode {
                // In essence mode, show only the first occurrence of each unique pattern
                let line_text = &group.first().normalized;
                result.push_str(line_text);
                // Track lines saved (all duplicate lines in the group)
                if group.count() > 1 {
                    self.stats.lines_saved += group.count() - 1;
                }
            } else {
                // Standard mode: output all lines individually (with optional PII masking)
                for (i, line) in group.lines.iter().enumerate() {
                    if i > 0 {
                        result.push('\n');
                    }

                    // Apply PII masking if enabled
                    let line_output = if self.config.sanitize_pii {
                        apply_pii_masking(&line.original, &line.tokens)
                    } else {
                        line.original.clone()
                    };
                    result.push_str(&line_output);
                }
            }
            Ok(result)
        }
    }

    pub fn print_stats<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Calculate metrics
        let compression_ratio = if self.stats.total_lines > 0 {
            (self.stats.lines_saved as f64 / self.stats.total_lines as f64) * 100.0
        } else {
            0.0
        };

        let output_lines = self.stats.output_lines;

        // Output markdown report
        writeln!(writer, "\n---")?;
        writeln!(writer, "# lessence Compression Report")?;
        writeln!(
            writer,
            "*Generated by lessence v{} on {}*",
            env!("CARGO_PKG_VERSION"),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        )?;
        writeln!(writer)?;
        writeln!(writer, "## Summary")?;
        writeln!(writer, "- **Original**: {} lines", self.stats.total_lines)?;
        writeln!(
            writer,
            "- **Compressed**: {output_lines} lines ({compression_ratio:.1}% reduction)"
        )?;
        writeln!(
            writer,
            "- **Patterns detected**: {} across {} categories",
            self.stats.patterns_detected,
            self.count_active_pattern_types()
        )?;
        writeln!(
            writer,
            "- **Collapsed groups**: {} ({} lines saved)",
            self.stats.collapsed_groups, self.stats.lines_saved
        )?;
        writeln!(writer)?;

        // Pattern distribution table
        writeln!(writer, "## Pattern Distribution")?;
        writeln!(writer, "| Pattern Type | Count | Description |")?;
        writeln!(writer, "|--------------|-------|-------------|")?;

        if self.stats.timestamps > 0 {
            writeln!(
                writer,
                "| Timestamps | {} | Log timestamps, dates, times |",
                self.stats.timestamps
            )?;
        }
        if self.stats.ips > 0 {
            writeln!(
                writer,
                "| IP Addresses | {} | IPv4, IPv6, ports, network addresses |",
                self.stats.ips
            )?;
        }
        if self.stats.hashes > 0 {
            writeln!(
                writer,
                "| Hashes | {} | Pod UIDs, container IDs, volume names, checksums |",
                self.stats.hashes
            )?;
        }
        if self.stats.uuids > 0 {
            writeln!(
                writer,
                "| UUIDs | {} | Request IDs, trace IDs, unique identifiers |",
                self.stats.uuids
            )?;
        }
        if self.stats.durations > 0 {
            writeln!(
                writer,
                "| Durations | {} | Timeouts, latencies, elapsed times |",
                self.stats.durations
            )?;
        }
        if self.stats.pids > 0 {
            writeln!(
                writer,
                "| Process IDs | {} | PIDs, thread IDs, process identifiers |",
                self.stats.pids
            )?;
        }
        if self.stats.sizes > 0 {
            writeln!(
                writer,
                "| File Sizes | {} | Memory usage, file sizes, data volumes |",
                self.stats.sizes
            )?;
        }
        if self.stats.percentages > 0 {
            writeln!(
                writer,
                "| Numbers/Percentages | {} | CPU usage, percentages, metrics |",
                self.stats.percentages
            )?;
        }
        if self.stats.http_status > 0 {
            writeln!(
                writer,
                "| HTTP Status | {} | Response codes, error codes |",
                self.stats.http_status
            )?;
        }
        if self.stats.paths > 0 {
            writeln!(
                writer,
                "| File Paths | {} | File paths, URLs, directories |",
                self.stats.paths
            )?;
        }
        if self.stats.kubernetes > 0 {
            writeln!(
                writer,
                "| Kubernetes | {} | Namespaces, volumes, plugins, pod names |",
                self.stats.kubernetes
            )?;
        }
        if self.stats.emails > 0 {
            writeln!(
                writer,
                "| Email Addresses | {} | RFC 5322 email addresses, user accounts |",
                self.stats.emails
            )?;
        }

        writeln!(writer)?;

        // Analysis guidance
        writeln!(writer, "## Recommendations for Analysis")?;
        if compression_ratio > 90.0 {
            writeln!(
                writer,
                "- **High compression ratio** ({compression_ratio:.1}%) indicates many repetitive patterns"
            )?;
        } else if compression_ratio > 70.0 {
            writeln!(
                writer,
                "- **Moderate compression ratio** ({compression_ratio:.1}%) indicates some repetitive patterns"
            )?;
        } else {
            writeln!(
                writer,
                "- **Low compression ratio** ({compression_ratio:.1}%) indicates diverse log content"
            )?;
        }

        writeln!(
            writer,
            "- **Search strategy**: Use compressed output to identify error types, then grep original logs for details"
        )?;
        writeln!(
            writer,
            "- **Variation indicators**: Pay attention to `[+N similar, varying: X, Y]` to understand what changes between similar errors"
        )?;
        writeln!(
            writer,
            "- **Focus areas**: Unique error messages that couldn't be compressed likely indicate distinct issues"
        )?;

        if self.stats.collapsed_groups > 50 {
            writeln!(
                writer,
                "- **High pattern repetition**: {} collapsed groups suggest systematic issues worth investigating",
                self.stats.collapsed_groups
            )?;
        }

        writeln!(writer, "---")?;

        Ok(())
    }

    pub fn print_stats_json(&self, elapsed: Duration) -> Result<()> {
        let compression_ratio = if self.stats.total_lines > 0 {
            (self.stats.lines_saved as f64 / self.stats.total_lines as f64) * 100.0
        } else {
            0.0
        };

        let stats_json = StatsJson {
            input_lines: self.stats.total_lines,
            output_lines: self.stats.output_lines,
            compression_ratio,
            collapsed_groups: self.stats.collapsed_groups,
            lines_saved: self.stats.lines_saved,
            patterns_detected: self.stats.patterns_detected,
            elapsed_ms: elapsed.as_millis() as u64,
            pattern_hits: PatternHits {
                timestamps: self.stats.timestamps,
                ips: self.stats.ips,
                hashes: self.stats.hashes,
                uuids: self.stats.uuids,
                pids: self.stats.pids,
                durations: self.stats.durations,
                http_status: self.stats.http_status,
                sizes: self.stats.sizes,
                percentages: self.stats.percentages,
                paths: self.stats.paths,
                kubernetes: self.stats.kubernetes,
                emails: self.stats.emails,
            },
        };

        let stderr = io::stderr();
        let mut handle = stderr.lock();
        serde_json::to_writer(&mut handle, &stats_json)?;
        writeln!(handle)?;
        Ok(())
    }

    fn count_active_pattern_types(&self) -> usize {
        let mut count = 0;
        if self.stats.timestamps > 0 {
            count += 1;
        }
        if self.stats.ips > 0 {
            count += 1;
        }
        if self.stats.hashes > 0 {
            count += 1;
        }
        if self.stats.uuids > 0 {
            count += 1;
        }
        if self.stats.durations > 0 {
            count += 1;
        }
        if self.stats.pids > 0 {
            count += 1;
        }
        if self.stats.sizes > 0 {
            count += 1;
        }
        if self.stats.percentages > 0 {
            count += 1;
        }
        if self.stats.http_status > 0 {
            count += 1;
        }
        if self.stats.paths > 0 {
            count += 1;
        }
        if self.stats.kubernetes > 0 {
            count += 1;
        }
        count
    }

    /// Parallel batch processing: normalize in parallel, cluster sequentially
    fn process_batch(&mut self) -> Result<()> {
        let batch = std::mem::take(&mut self.batch_buffer);
        let processed_lines = self.parallel_pattern_detection(&batch)?;

        for processed_line in processed_lines {
            self.sequential_clustering(processed_line)?;
        }
        Ok(())
    }

    /// Phase 1: Parallel pattern detection and normalization (the CPU-intensive work)
    fn parallel_pattern_detection(&self, lines: &[String]) -> Result<Vec<LogLine>> {
        use rayon::prelude::*;

        // This is where the real CPU work happens - parallel regex pattern detection
        let processed_lines: Vec<LogLine> = lines
            .par_iter()
            .map(|line| {
                // CPU-intensive pattern detection - perfectly parallelizable
                self.normalizer.normalize_line(line.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(processed_lines)
    }

    /// Phase 2: Fast sequential clustering using pre-computed normalized lines
    fn sequential_clustering(&mut self, normalized_line: LogLine) -> Result<()> {
        // Fast clustering using pre-computed patterns and hashes
        if !normalized_line.tokens.is_empty() {
            self.stats.patterns_detected += 1;
            self.count_pattern_types(&normalized_line.tokens);
        }

        // Fast similarity matching using pre-computed normalized text
        let mut match_index = None;
        for (i, group) in self.buffer.iter().enumerate() {
            if self.normalizer.are_similar(&normalized_line, group.first()) {
                match_index = Some(i);
                break;
            }
        }

        if let Some(index) = match_index {
            // In parallel mode, position_counter is the end-of-batch position,
            // not the per-line position. Line numbers in parallel mode are
            // therefore approximate — accurate single-threaded, batch-granular
            // parallel. Documented in the JSON schema.
            self.buffer[index].add_line(normalized_line, self.position_counter);
        } else {
            self.buffer
                .push(PatternGroup::new(normalized_line, self.position_counter));
        }

        Ok(())
    }

    /// Sequential processing for constitutional compliance (used internally)
    /// Get current statistics (for preflight analysis)
    pub fn get_stats(&self) -> &FoldingStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::HashType;

    // ---------------------------------------------------------------
    // Helpers for building synthetic test data
    // ---------------------------------------------------------------

    /// Build a LogLine with the given tokens and a normalized template.
    fn make_line(normalized: &str, tokens: Vec<Token>) -> LogLine {
        LogLine {
            original: normalized.to_string(),
            normalized: normalized.to_string(),
            tokens,
            hash: 0,
        }
    }

    /// Build a PatternGroup with N lines, each having the given tokens.
    /// All lines share the same normalized template.
    fn make_group(normalized: &str, lines: Vec<Vec<Token>>) -> PatternGroup {
        assert!(!lines.is_empty(), "group must have at least one line");
        let mut group = PatternGroup::new(make_line(normalized, lines[0].clone()), 1);
        for (i, tokens) in lines.into_iter().enumerate().skip(1) {
            group.add_line(make_line(normalized, tokens), i + 2);
        }
        group
    }

    // ---------------------------------------------------------------
    // apply_pii_masking
    // ---------------------------------------------------------------

    #[test]
    fn pii_masking_no_emails() {
        let result = apply_pii_masking("no emails here", &[]);
        assert_eq!(result, "no emails here");
    }

    #[test]
    fn pii_masking_single_email() {
        let tokens = vec![Token::Email("alice@co.com".into())];
        let result = apply_pii_masking("User alice@co.com logged in", &tokens);
        assert_eq!(result, "User <EMAIL> logged in");
    }

    #[test]
    fn pii_masking_duplicate_email_in_line() {
        // Kills mutant: `start + pos` → `start * pos` (line 39).
        // Second occurrence requires non-zero `start` for correct indexing.
        let tokens = vec![Token::Email("bob@x.com".into())];
        let result = apply_pii_masking("from bob@x.com to bob@x.com", &tokens);
        assert_eq!(result, "from <EMAIL> to <EMAIL>");
    }

    #[test]
    fn pii_masking_multiple_different_emails() {
        let tokens = vec![
            Token::Email("a@b.com".into()),
            Token::Email("c@d.com".into()),
        ];
        let result = apply_pii_masking("a@b.com and c@d.com", &tokens);
        assert_eq!(result, "<EMAIL> and <EMAIL>");
    }

    #[test]
    fn pii_masking_non_email_tokens_ignored() {
        let tokens = vec![
            Token::IPv4("10.0.0.1".into()),
            Token::Email("x@y.com".into()),
        ];
        let result = apply_pii_masking("10.0.0.1 x@y.com", &tokens);
        assert_eq!(result, "10.0.0.1 <EMAIL>");
    }

    // ---------------------------------------------------------------
    // first_timestamp_in
    // ---------------------------------------------------------------

    #[test]
    fn first_timestamp_no_tokens() {
        assert_eq!(first_timestamp_in(&[]), None);
    }

    #[test]
    fn first_timestamp_no_timestamps() {
        let tokens = vec![Token::IPv4("1.2.3.4".into()), Token::Pid(42)];
        assert_eq!(first_timestamp_in(&tokens), None);
    }

    #[test]
    fn first_timestamp_single() {
        let tokens = vec![Token::Timestamp("10:00:00".into())];
        assert_eq!(first_timestamp_in(&tokens), Some("10:00:00".into()));
    }

    #[test]
    fn first_timestamp_multiple_returns_first() {
        let tokens = vec![
            Token::IPv4("1.2.3.4".into()),
            Token::Timestamp("10:00:00".into()),
            Token::Timestamp("11:00:00".into()),
        ];
        assert_eq!(first_timestamp_in(&tokens), Some("10:00:00".into()));
    }

    // ---------------------------------------------------------------
    // Existing folding tests
    // ---------------------------------------------------------------

    #[test]
    fn test_simple_folding() -> Result<()> {
        let config = Config::default();
        let mut folder = PatternFolder::new(config);

        let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
        let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
        let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        let result = folder.process_line(line3)?;

        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_folding_with_finish() -> Result<()> {
        let config = Config {
            min_collapse: 2,
            ..Config::default()
        };

        let mut folder = PatternFolder::new(config);

        let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
        let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
        let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        folder.process_line(line3)?;

        let results = folder.finish()?;
        assert!(!results.is_empty());

        let output = results.join("\n");
        assert!(
            output.contains("similar"),
            "Expected 'similar' in compact output, got: {output}"
        );

        Ok(())
    }

    #[test]
    fn test_no_folding_for_different_lines() -> Result<()> {
        let config = Config::default();
        let mut folder = PatternFolder::new(config);

        let line1 = "2025-01-20 10:15:01 Starting application";
        let line2 = "2025-01-20 10:15:02 Loading configuration";
        let line3 = "2025-01-20 10:15:03 Database connected";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        folder.process_line(line3)?;

        let results = folder.finish()?;
        let output = results.join("\n");

        assert!(!output.contains("collapsed"));
        assert!(output.contains("Starting application"));
        assert!(output.contains("Loading configuration"));
        assert!(output.contains("Database connected"));

        Ok(())
    }

    // ---------------------------------------------------------------
    // seed_for_group — FNV-1a determinism
    // ---------------------------------------------------------------

    #[test]
    fn seed_for_group_pinned_values() {
        // Pin FNV-1a outputs so any implementation drift is caught.
        assert_eq!(seed_for_group("hello"), 0xa430_d846_80aa_bd0b);
        assert_eq!(seed_for_group("world"), 0x4f59_ff5e_730c_8af3);
    }

    #[test]
    fn seed_for_group_empty_string_is_offset_basis() {
        // Empty string → no XOR/multiply iterations → returns FNV offset basis.
        assert_eq!(seed_for_group(""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn seed_for_group_different_inputs_different_seeds() {
        let a = seed_for_group("template A: <UUID> failed");
        let b = seed_for_group("template B: <IP> connected");
        assert_ne!(a, b);
    }

    // ---------------------------------------------------------------
    // hash_token_value — FNV-1a on token canonical strings
    // ---------------------------------------------------------------

    #[test]
    fn hash_token_value_matches_seed_for_same_string() {
        // hash_token_value(Name("hello")) should equal seed_for_group("hello")
        // because both use the same FNV-1a over the same bytes.
        let token = Token::Name("hello".to_string());
        assert_eq!(hash_token_value(&token), seed_for_group("hello"));
    }

    #[test]
    fn hash_token_value_different_tokens_different_hashes() {
        let a = hash_token_value(&Token::Pid(1234));
        let b = hash_token_value(&Token::Pid(5678));
        assert_ne!(a, b);
    }

    // ---------------------------------------------------------------
    // is_sample_worthy — exhaustiveness
    // ---------------------------------------------------------------

    #[test]
    fn is_sample_worthy_covers_all_token_variants() {
        // Build one instance of every Token variant. If a new variant is
        // added to the enum without updating this test, it won't compile.
        let all_tokens: Vec<(Token, bool)> = vec![
            // Sample-worthy types (true)
            (Token::Uuid("u".into()), true),
            (Token::IPv4("1.2.3.4".into()), true),
            (Token::IPv6("::1".into()), true),
            (Token::Path("/a".into()), true),
            (Token::Email("a@b".into()), true),
            (Token::Hash(HashType::MD5, "abc".into()), true),
            (Token::KubernetesNamespace("ns".into()), true),
            (Token::VolumeName("vol".into()), true),
            (Token::PluginType("csi".into()), true),
            (Token::PodName("pod".into()), true),
            (Token::QuotedString("q".into()), true),
            (Token::Name("n".into()), true),
            (Token::HttpStatus(200), true),
            (Token::HttpStatusClass("2xx".into()), true),
            (Token::BracketContext(vec!["err".into()]), true),
            (Token::Json("{}".into()), true),
            // Count-only types (false)
            (Token::Timestamp("ts".into()), false),
            (Token::Port(80), false),
            (Token::Pid(1), false),
            (Token::ThreadID("t1".into()), false),
            (Token::Duration("1s".into()), false),
            (Token::Size("1KB".into()), false),
            (Token::Number("42".into()), false),
            (
                Token::KeyValuePair {
                    key: "k".into(),
                    value_type: "v".into(),
                },
                false,
            ),
            (
                Token::LogWithModule {
                    level: "INFO".into(),
                    module: "m".into(),
                },
                false,
            ),
            (
                Token::StructuredMessage {
                    component: "c".into(),
                    level: "l".into(),
                },
                false,
            ),
        ];

        for (token, expected) in &all_tokens {
            assert_eq!(
                is_sample_worthy(token),
                *expected,
                "is_sample_worthy({:?}) should be {expected}",
                token_type_name(token)
            );
        }

        // Verify we covered all 26 variants (24 original + any new ones).
        // Update this count if Token gains new variants.
        assert_eq!(
            all_tokens.len(),
            26,
            "Token enum may have new variants — update this test"
        );
    }

    // ---------------------------------------------------------------
    // token_type_name — exhaustiveness
    // ---------------------------------------------------------------

    #[test]
    fn token_type_name_covers_all_variants() {
        // Every Token variant must return a non-empty UPPERCASE name.
        let tokens: Vec<Token> = vec![
            Token::Timestamp("ts".into()),
            Token::IPv4("1.2.3.4".into()),
            Token::IPv6("::1".into()),
            Token::Port(80),
            Token::Hash(HashType::SHA256, "h".into()),
            Token::Uuid("u".into()),
            Token::Pid(1),
            Token::ThreadID("t".into()),
            Token::Path("/p".into()),
            Token::Json("{}".into()),
            Token::Duration("1s".into()),
            Token::Size("1K".into()),
            Token::Number("1".into()),
            Token::HttpStatus(200),
            Token::QuotedString("q".into()),
            Token::Name("n".into()),
            Token::KubernetesNamespace("ns".into()),
            Token::VolumeName("v".into()),
            Token::PluginType("p".into()),
            Token::PodName("pod".into()),
            Token::HttpStatusClass("2xx".into()),
            Token::BracketContext(vec![]),
            Token::KeyValuePair {
                key: "k".into(),
                value_type: "v".into(),
            },
            Token::LogWithModule {
                level: "INFO".into(),
                module: "m".into(),
            },
            Token::StructuredMessage {
                component: "c".into(),
                level: "l".into(),
            },
            Token::Email("e@e".into()),
        ];

        for token in &tokens {
            let name = token_type_name(token);
            assert!(
                !name.is_empty(),
                "token_type_name returned empty for {token:?}",
            );
            assert_eq!(
                name,
                name.to_uppercase(),
                "token_type_name should return UPPERCASE: got {name}"
            );
        }
    }

    // ---------------------------------------------------------------
    // token_value_string — no panics on any variant
    // ---------------------------------------------------------------

    #[test]
    fn token_value_string_handles_all_variants() {
        let tokens: Vec<Token> = vec![
            Token::Timestamp("2025-01-01".into()),
            Token::IPv4("10.0.0.1".into()),
            Token::IPv6("::1".into()),
            Token::Port(443),
            Token::Hash(HashType::SHA1, "abc123".into()),
            Token::Uuid("550e8400-e29b-41d4-a716-446655440000".into()),
            Token::Pid(9999),
            Token::ThreadID("worker-3".into()),
            Token::Path("/var/log/app.log".into()),
            Token::Json(r#"{"key":"val"}"#.into()),
            Token::Duration("3.5s".into()),
            Token::Size("2MB".into()),
            Token::Number("42".into()),
            Token::HttpStatus(404),
            Token::QuotedString("hello world".into()),
            Token::Name("myapp".into()),
            Token::KubernetesNamespace("kube-system".into()),
            Token::VolumeName("pvc-data".into()),
            Token::PluginType("csi-driver".into()),
            Token::PodName("api-server-xyz".into()),
            Token::HttpStatusClass("5xx".into()),
            Token::BracketContext(vec!["error".into(), "handler".into()]),
            Token::KeyValuePair {
                key: "user".into(),
                value_type: "string".into(),
            },
            Token::LogWithModule {
                level: "WARN".into(),
                module: "net".into(),
            },
            Token::StructuredMessage {
                component: "api".into(),
                level: "error".into(),
            },
            Token::Email("user@example.com".into()),
        ];

        for token in &tokens {
            let val = token_value_string(token);
            assert!(
                !val.is_empty(),
                "token_value_string returned empty for {:?}",
                token_type_name(token)
            );
        }

        // Spot-check specific formats
        assert_eq!(
            token_value_string(&Token::BracketContext(vec![
                "error".into(),
                "handler".into()
            ])),
            "error,handler"
        );
        assert_eq!(token_value_string(&Token::Port(443)), "443");
        assert_eq!(token_value_string(&Token::HttpStatus(404)), "404");
        assert_eq!(token_value_string(&Token::Pid(9999)), "9999");
        assert_eq!(
            token_value_string(&Token::KeyValuePair {
                key: "k".into(),
                value_type: "v".into()
            }),
            "k=v"
        );
    }

    // ---------------------------------------------------------------
    // RollupComputer::compute — hand-crafted groups
    // ---------------------------------------------------------------

    #[test]
    fn rollup_empty_group_no_tokens() {
        let rc = RollupComputer::with_defaults();
        let group = make_group("no tokens here", vec![vec![]]);
        let rollup = rc.compute(&group);
        assert!(
            rollup.is_empty(),
            "empty-token group should produce empty rollup"
        );
    }

    #[test]
    fn rollup_single_sample_worthy_token() {
        let rc = RollupComputer::with_defaults();
        let group = make_group(
            "request <UUID> failed",
            vec![vec![Token::Uuid("aaa-bbb".into())]],
        );
        let rollup = rc.compute(&group);
        let entry = rollup.get("UUID").expect("UUID should be in rollup");
        assert_eq!(entry.distinct_count, 1);
        assert_eq!(entry.samples, vec!["aaa-bbb"]);
        assert!(!entry.capped);
    }

    #[test]
    fn rollup_single_count_only_token() {
        let rc = RollupComputer::with_defaults();
        let group = make_group(
            "<TIMESTAMP> started",
            vec![vec![Token::Timestamp("2025-01-01 10:00:00".into())]],
        );
        let rollup = rc.compute(&group);
        let entry = rollup
            .get("TIMESTAMP")
            .expect("TIMESTAMP should be in rollup");
        assert_eq!(entry.distinct_count, 1);
        assert!(
            entry.samples.is_empty(),
            "count-only type must have empty samples"
        );
        assert!(!entry.capped);
    }

    #[test]
    fn rollup_mixed_tokens_across_lines() {
        let rc = RollupComputer::with_defaults();
        let lines: Vec<Vec<Token>> = (0..5)
            .map(|i| {
                vec![
                    Token::Uuid(format!("uuid-{}", i % 3)), // 3 distinct
                    Token::Timestamp(format!("ts-{i}")),    // 5 distinct
                ]
            })
            .collect();
        let group = make_group("request <UUID> at <TIMESTAMP>", lines);
        let rollup = rc.compute(&group);

        let uuid_entry = rollup.get("UUID").unwrap();
        assert_eq!(uuid_entry.distinct_count, 3);
        assert_eq!(uuid_entry.samples.len(), 3); // 3 <= K, so all shown
        assert!(!uuid_entry.capped);

        let ts_entry = rollup.get("TIMESTAMP").unwrap();
        assert_eq!(ts_entry.distinct_count, 5);
        assert!(ts_entry.samples.is_empty(), "TIMESTAMP is count-only");
        assert!(!ts_entry.capped);
    }

    #[test]
    fn rollup_exactly_at_cap_is_not_capped() {
        let rc = RollupComputer::with_defaults();
        // ROLLUP_DISTINCT_CAP = 64. Generate exactly 64 distinct UUIDs.
        let lines: Vec<Vec<Token>> = (0..64)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group = make_group("request <UUID>", lines);
        let rollup = rc.compute(&group);

        let entry = rollup.get("UUID").unwrap();
        assert_eq!(entry.distinct_count, 64);
        assert!(!entry.capped, "exactly at cap should NOT be capped");
    }

    #[test]
    fn rollup_one_over_cap_is_capped() {
        let rc = RollupComputer::with_defaults();
        // 65 distinct UUIDs: first 64 are inserted, 65th triggers the cap.
        let lines: Vec<Vec<Token>> = (0..65)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group = make_group("request <UUID>", lines);
        let rollup = rc.compute(&group);

        let entry = rollup.get("UUID").unwrap();
        assert_eq!(entry.distinct_count, 64, "capped at ROLLUP_DISTINCT_CAP");
        assert!(entry.capped, "65th value should trigger capped flag");
    }

    #[test]
    fn rollup_samples_capped_at_k() {
        let rc = RollupComputer::with_defaults();
        // ROLLUP_K = 7. Create 8 distinct UUIDs — samples should have 7.
        let lines: Vec<Vec<Token>> = (0..8)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group = make_group("request <UUID>", lines);
        let rollup = rc.compute(&group);

        let entry = rollup.get("UUID").unwrap();
        assert_eq!(entry.distinct_count, 8);
        assert_eq!(
            entry.samples.len(),
            ROLLUP_K,
            "samples should be capped at K={ROLLUP_K}"
        );
    }

    #[test]
    fn rollup_deterministic_across_calls() {
        let rc = RollupComputer::with_defaults();
        let lines: Vec<Vec<Token>> = (0..20)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group = make_group("request <UUID>", lines);

        let rollup1 = rc.compute(&group);
        let rollup2 = rc.compute(&group);
        assert_eq!(rollup1, rollup2, "same group must produce identical rollup");
    }

    #[test]
    fn rollup_different_templates_different_samples() {
        let rc = RollupComputer::with_defaults();
        // Same 20 values, but different normalized templates → different seeds.
        let tokens: Vec<Vec<Token>> = (0..20)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group_a = make_group("template A: <UUID>", tokens.clone());
        let group_b = make_group("template B: <UUID>", tokens);

        let rollup_a = rc.compute(&group_a);
        let rollup_b = rc.compute(&group_b);

        let samples_a = &rollup_a.get("UUID").unwrap().samples;
        let samples_b = &rollup_b.get("UUID").unwrap().samples;

        // Both have 7 samples drawn from the same 20 values but with
        // different seeds, so the draws should (almost certainly) differ.
        // This is probabilistic but with 20-choose-7 there are 77520
        // possible draws — collision chance is negligible.
        assert_ne!(
            samples_a, samples_b,
            "different templates should (almost certainly) produce different sample draws"
        );
    }

    #[test]
    fn rollup_samples_are_sorted() {
        let rc = RollupComputer::with_defaults();
        let lines: Vec<Vec<Token>> = (0..15)
            .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
            .collect();
        let group = make_group("request <UUID>", lines);
        let rollup = rc.compute(&group);

        let entry = rollup.get("UUID").unwrap();
        let mut sorted = entry.samples.clone();
        sorted.sort();
        assert_eq!(
            entry.samples, sorted,
            "samples must be lexicographically sorted"
        );
    }

    #[test]
    fn rollup_variation_keys_are_sorted() {
        let rc = RollupComputer::with_defaults();
        let group = make_group(
            "mixed",
            vec![vec![
                Token::Uuid("u".into()),
                Token::IPv4("1.2.3.4".into()),
                Token::Path("/a".into()),
            ]],
        );
        let rollup = rc.compute(&group);
        let keys: Vec<&&str> = rollup.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "variation keys must be alphabetically sorted (BTreeMap)"
        );
    }

    // ---------------------------------------------------------------
    // render_compact_marker
    // ---------------------------------------------------------------

    #[test]
    fn marker_empty_rollup() {
        let result = render_compact_marker(42, &BTreeMap::new(), None, None, 3, false);
        assert_eq!(result, "[+42 similar]");
    }

    #[test]
    fn marker_inline_samples_below_threshold() {
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "PATH",
            VariationEntry {
                distinct_count: 2,
                samples: vec!["/var/a".into(), "/var/b".into()],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        assert_eq!(result, "[+10 similar | path×2 {/var/a, /var/b}]");
    }

    #[test]
    fn marker_count_only_above_threshold() {
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "PATH",
            VariationEntry {
                distinct_count: 5,
                samples: vec![
                    "/a".into(),
                    "/b".into(),
                    "/c".into(),
                    "/d".into(),
                    "/e".into(),
                ],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        // distinct > threshold → count-only, no inline samples
        assert_eq!(result, "[+10 similar | path×5]");
    }

    #[test]
    fn marker_capped_entry_has_plus_suffix() {
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "HASH",
            VariationEntry {
                distinct_count: 64,
                samples: vec!["abc".into(), "def".into()],
                capped: true,
            },
        );
        let result = render_compact_marker(100, &rollup, None, None, 3, false);
        assert!(
            result.contains("hash×64+"),
            "capped entry needs '+': {result}"
        );
        // Capped entries should NOT show inline samples regardless of threshold
        assert!(
            !result.contains('{'),
            "capped entry should not inline samples: {result}"
        );
    }

    #[test]
    fn marker_time_range_present() {
        let result = render_compact_marker(
            5,
            &BTreeMap::new(),
            Some("10:00:00"),
            Some("10:05:00"),
            3,
            false,
        );
        assert_eq!(result, "[+5 similar | 10:00:00 → 10:05:00]");
    }

    #[test]
    fn marker_time_range_suppressed_in_essence_mode() {
        let result = render_compact_marker(
            5,
            &BTreeMap::new(),
            Some("10:00:00"),
            Some("10:05:00"),
            3,
            true, // essence mode
        );
        assert_eq!(
            result, "[+5 similar]",
            "essence mode must suppress time range"
        );
    }

    #[test]
    fn marker_sample_truncation_at_50_chars() {
        let mut rollup: GroupRollup = BTreeMap::new();
        let long_value = "a".repeat(51); // 51 chars → should be truncated
        let exact_value = "b".repeat(50); // 50 chars → should NOT be truncated
        rollup.insert(
            "PATH",
            VariationEntry {
                distinct_count: 2,
                samples: vec![exact_value.clone(), long_value],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        // 50-char value: not truncated
        assert!(
            result.contains(&exact_value),
            "50-char value should not be truncated"
        );
        // 51-char value: truncated to 49 chars + '…'
        let truncated = format!("{}…", "a".repeat(49));
        assert!(
            result.contains(&truncated),
            "51-char value should be truncated to 49+…: {result}"
        );
    }

    #[test]
    fn marker_multiple_entries_comma_separated() {
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "IPV4",
            VariationEntry {
                distinct_count: 4,
                samples: vec!["10.0.0.1".into(), "10.0.0.2".into()],
                capped: false,
            },
        );
        rollup.insert(
            "UUID",
            VariationEntry {
                distinct_count: 7,
                samples: vec!["aaa".into(), "bbb".into()],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        // BTreeMap order: IPV4 before UUID
        assert!(
            result.contains("ipv4×4, uuid×7"),
            "entries should be comma-separated, lowercase: {result}"
        );
    }

    #[test]
    fn marker_count_only_types_filtered_out() {
        // Count-only types (empty samples, distinct > 0) should not appear
        // in the marker unless distinct_count <= inline_threshold.
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "TIMESTAMP",
            VariationEntry {
                distinct_count: 500,
                samples: vec![],
                capped: false,
            },
        );
        rollup.insert(
            "UUID",
            VariationEntry {
                distinct_count: 3,
                samples: vec!["a".into(), "b".into(), "c".into()],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        assert!(
            !result.contains("timestamp"),
            "count-only type with high cardinality should be filtered: {result}"
        );
        assert!(
            result.contains("uuid×3"),
            "sample-worthy type should appear: {result}"
        );
    }

    // ---------------------------------------------------------------
    // Mutant-killing tests (targeted at cargo-mutants survivors)
    // ---------------------------------------------------------------

    #[test]
    fn marker_zero_distinct_count_filtered_out() {
        // Kills mutant: `distinct_count > 0` → `distinct_count >= 0`
        // An entry with distinct_count=0 should never appear in the marker.
        let mut rollup: GroupRollup = BTreeMap::new();
        rollup.insert(
            "UUID",
            VariationEntry {
                distinct_count: 0,
                samples: vec![],
                capped: false,
            },
        );
        let result = render_compact_marker(10, &rollup, None, None, 3, false);
        assert_eq!(
            result, "[+10 similar]",
            "zero-distinct entry must be filtered out"
        );
    }

    #[test]
    fn marker_truncation_exact_length() {
        // Kills mutants: `SAMPLE_MAX_LEN - 1` → `+ 1` or `/ 1`
        // The truncated output must be exactly 50 chars (49 content + '…').
        let mut rollup: GroupRollup = BTreeMap::new();
        let long_value = "x".repeat(100);
        rollup.insert(
            "PATH",
            VariationEntry {
                distinct_count: 1,
                samples: vec![long_value],
                capped: false,
            },
        );
        let result = render_compact_marker(5, &rollup, None, None, 3, false);
        // Extract the truncated sample from the marker: between { and }
        let start = result.find('{').expect("should have inline samples") + 1;
        let end = result.find('}').expect("should have closing brace");
        let rendered_sample = &result[start..end];
        // 49 'x' chars + '…' = 50 chars total
        assert_eq!(
            rendered_sample.chars().count(),
            50,
            "truncated sample should be exactly 50 chars: got '{rendered_sample}'"
        );
        assert!(
            rendered_sample.ends_with('…'),
            "truncated sample should end with '…': got '{rendered_sample}'"
        );
        assert_eq!(
            rendered_sample.chars().filter(|&c| c == 'x').count(),
            49,
            "should have 49 content chars before '…'"
        );
    }

    // ---------------------------------------------------------------
    // Property-based tests for rollup invariants
    // ---------------------------------------------------------------

    mod rollup_properties {
        use super::*;
        use proptest::collection::vec as pvec;
        use proptest::prelude::*;

        /// Generate a random sample-worthy token with a random string value.
        fn arb_sample_worthy_token() -> impl Strategy<Value = Token> {
            ("[a-z0-9]{1,20}", 0..6u8).prop_map(|(val, variant)| match variant {
                0 => Token::Uuid(val),
                1 => Token::IPv4(val),
                2 => Token::Path(val),
                3 => Token::Name(val),
                4 => Token::Email(val),
                _ => Token::QuotedString(val),
            })
        }

        /// Generate a random count-only token.
        fn arb_count_only_token() -> impl Strategy<Value = Token> {
            ("[a-z0-9]{1,20}", 0..4u8).prop_map(|(val, variant)| match variant {
                0 => Token::Timestamp(val),
                1 => Token::Duration(val),
                2 => Token::Number(val),
                _ => Token::Size(val),
            })
        }

        /// Generate a random token (either sample-worthy or count-only).
        fn arb_token() -> impl Strategy<Value = Token> {
            prop_oneof![arb_sample_worthy_token(), arb_count_only_token(),]
        }

        /// Generate a random PatternGroup for property testing.
        fn arb_group() -> impl Strategy<Value = PatternGroup> {
            (
                "[a-z ]{5,30}",                       // normalized template
                pvec(pvec(arb_token(), 0..8), 1..50), // 1-49 lines, 0-7 tokens each
            )
                .prop_map(|(normalized, token_lines)| make_group(&normalized, token_lines))
        }

        proptest! {
            #[test]
            fn samples_never_exceed_k(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                for (name, entry) in &rollup {
                    prop_assert!(
                        entry.samples.len() <= ROLLUP_K,
                        "{name}: samples.len()={} > K={ROLLUP_K}",
                        entry.samples.len()
                    );
                }
            }

            #[test]
            fn capped_implies_distinct_at_cap(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                for (name, entry) in &rollup {
                    if entry.capped {
                        prop_assert!(
                            entry.distinct_count >= ROLLUP_DISTINCT_CAP,
                            "{name}: capped=true but distinct_count={} < cap={ROLLUP_DISTINCT_CAP}",
                            entry.distinct_count
                        );
                    }
                }
            }

            #[test]
            fn not_capped_implies_distinct_under_cap(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                for (name, entry) in &rollup {
                    if !entry.capped {
                        prop_assert!(
                            entry.distinct_count <= ROLLUP_DISTINCT_CAP,
                            "{name}: capped=false but distinct_count={} > cap={ROLLUP_DISTINCT_CAP}",
                            entry.distinct_count
                        );
                    }
                }
            }

            #[test]
            fn count_only_types_always_empty_samples(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                const COUNT_ONLY: &[&str] = &[
                    "TIMESTAMP", "DURATION", "SIZE", "NUMBER",
                    "PORT", "PID", "THREAD_ID", "KEY_VALUE",
                    "LOG_WITH_MODULE", "STRUCTURED_MESSAGE",
                ];
                for name in COUNT_ONLY {
                    if let Some(entry) = rollup.get(name) {
                        prop_assert!(
                            entry.samples.is_empty(),
                            "{name}: count-only type has samples: {:?}",
                            entry.samples
                        );
                    }
                }
            }

            #[test]
            fn compute_is_deterministic(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let r1 = rc.compute(&group);
                let r2 = rc.compute(&group);
                prop_assert_eq!(r1, r2);
            }

            #[test]
            fn variation_keys_alphabetically_sorted(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                let keys: Vec<&&str> = rollup.keys().collect();
                let mut sorted = keys.clone();
                sorted.sort();
                prop_assert_eq!(keys, sorted);
            }

            #[test]
            fn samples_are_lexicographically_sorted(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                for (name, entry) in &rollup {
                    let mut sorted = entry.samples.clone();
                    sorted.sort();
                    prop_assert!(
                        entry.samples == sorted,
                        "{name}: samples not sorted: {:?}", entry.samples
                    );
                }
            }

            #[test]
            fn samples_subset_of_distinct_count(group in arb_group()) {
                let rc = RollupComputer::with_defaults();
                let rollup = rc.compute(&group);
                for (name, entry) in &rollup {
                    prop_assert!(
                        entry.samples.len() <= entry.distinct_count,
                        "{name}: samples.len()={} > distinct_count={}",
                        entry.samples.len(), entry.distinct_count
                    );
                }
            }
        }
    }
}
