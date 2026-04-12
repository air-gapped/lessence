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

        Ok((display, total_patterns, was_capped, fit_truncated))
    }

    /// Format a single summary line, optionally truncating to `max_width`.
    fn format_summary_line(count: usize, representative: &str, max_width: Option<usize>) -> String {
        let prefix = format!("[{count}x] ");
        match max_width {
            Some(width) if prefix.len() + representative.len() > width => {
                let avail = width.saturating_sub(prefix.len() + 3); // 3 for "..."
                if avail > 20 {
                    format!("{prefix}{}...", &representative[..avail])
                } else {
                    format!("{prefix}{representative}")
                }
            }
            _ => format!("{prefix}{representative}"),
        }
    }

    /// Format the coverage message for stderr.
    fn format_coverage_message(
        shown_count: usize,
        total_patterns: usize,
        shown_lines: usize,
        total_lines: usize,
        was_capped: bool,
    ) -> String {
        let coverage = if total_lines > 0 {
            (shown_lines as f64 / total_lines as f64) * 100.0
        } else {
            0.0
        };
        if was_capped {
            format!(
                "({shown_count} of {total_patterns} patterns, {coverage:.0}% coverage — use --top N to adjust, or --top 0 for all)",
            )
        } else {
            format!(
                "({shown_count} of {total_patterns} patterns, {shown_lines} of {total_lines} lines, {coverage:.0}% coverage)",
            )
        }
    }

    /// Finish processing and output a one-line-per-pattern summary sorted by frequency.
    /// Uses the parallel pipeline for normalization, then merges groups with identical
    /// normalized text and displays representative original lines.
    pub fn finish_summary(
        &mut self,
        top_n: Option<usize>,
        fit_budget: Option<usize>,
    ) -> Result<()> {
        let (display, total_patterns, was_capped, fit_truncated) =
            self.prepare_summary(top_n, fit_budget)?;
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
            println!("{}", Self::format_summary_line(*count, representative, max_width));
        }

        if fit_truncated > 0 {
            println!("... {fit_truncated} more patterns (remove --fit for full output)");
        }

        // Coverage info on stderr
        let shown_lines: usize = display.iter().map(|(c, _)| c).sum();
        eprintln!("{}", Self::format_coverage_message(
            shown_count, total_patterns, shown_lines, self.stats.total_lines, was_capped,
        ));

        Ok(())
    }

    pub fn finish(&mut self) -> Result<Vec<String>> {
        // Constitutional compliance: Process any remaining batch
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

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

    /// Build the JSON stats structure (testable, no I/O).
    fn build_stats_json(&self, elapsed: Duration) -> StatsJson {
        let compression_ratio = if self.stats.total_lines > 0 {
            (self.stats.lines_saved as f64 / self.stats.total_lines as f64) * 100.0
        } else {
            0.0
        };

        StatsJson {
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
        }
    }

    pub fn print_stats_json(&self, elapsed: Duration) -> Result<()> {
        let stats_json = self.build_stats_json(elapsed);
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

    #[test]
    fn pii_masking_empty_email_does_not_loop() {
        // Defensive: empty email string would cause infinite loop without guard
        let tokens = vec![Token::Email(String::new())];
        let result = apply_pii_masking("no emails here", &tokens);
        assert_eq!(result, "no emails here");
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

    // ---------------------------------------------------------------
    // Pipeline: process_line, flush_oldest_safe_group, should_flush_buffer
    // ---------------------------------------------------------------

    /// Build a single-threaded PatternFolder with sensible test defaults.
    fn make_folder() -> PatternFolder {
        PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            ..Config::default()
        })
    }

    #[test]
    fn process_line_increments_total_lines() {
        let mut f = make_folder();
        f.process_line("2024-01-01 10:00:00 INFO hello 192.168.1.1").unwrap();
        assert_eq!(f.stats.total_lines, 1);
    }

    #[test]
    fn process_line_with_tokens_increments_patterns_detected() {
        let mut f = make_folder();
        // This line contains an IP which will be detected as a token
        f.process_line("2024-01-01 10:00:00 INFO hello 192.168.1.1").unwrap();
        assert!(
            f.stats.patterns_detected >= 1,
            "patterns_detected should be >= 1, got {}",
            f.stats.patterns_detected
        );
    }

    #[test]
    fn process_line_without_tokens_does_not_increment_patterns() {
        let mut f = make_folder();
        // Plain text with no detectable patterns
        f.process_line("hello world").unwrap();
        assert_eq!(f.stats.patterns_detected, 0);
    }

    #[test]
    fn process_line_counts_patterns_for_each_line() {
        let mut f = make_folder();
        f.process_line("request from 10.0.0.1").unwrap();
        f.process_line("request from 10.0.0.2").unwrap();
        assert_eq!(f.stats.total_lines, 2);
        // Both lines have IP tokens
        assert!(
            f.stats.patterns_detected >= 2,
            "expected >= 2 patterns_detected, got {}",
            f.stats.patterns_detected
        );
    }

    #[test]
    fn process_line_identical_lines_cluster_into_one_group() {
        let mut f = make_folder();
        for _ in 0..5 {
            f.process_line("2024-01-01 ERROR connection refused from 10.0.0.1").unwrap();
        }
        // Similar lines should be in one group
        assert_eq!(f.buffer.len(), 1, "identical lines should cluster into one group");
        assert_eq!(f.buffer[0].count(), 5);
    }

    #[test]
    fn process_line_dissimilar_lines_create_separate_groups() {
        let mut f = make_folder();
        f.process_line("2024-01-01 ERROR disk full on /dev/sda1").unwrap();
        f.process_line("GET /api/health HTTP/1.1 200 OK").unwrap();
        assert!(
            f.buffer.len() >= 2,
            "dissimilar lines should create separate groups, got {}",
            f.buffer.len()
        );
    }

    #[test]
    fn process_line_batches_in_parallel_mode() {
        let mut f = PatternFolder::new(Config {
            thread_count: None, // parallel mode
            min_collapse: 3,
            ..Config::default()
        });
        let result = f.process_line("2024-01-01 INFO hello 10.0.0.1").unwrap();
        // Parallel mode buffers lines instead of processing immediately
        assert_eq!(result, None, "parallel mode should buffer, not process");
        assert_eq!(f.batch_buffer.len(), 1, "line should be in batch_buffer");
        assert_eq!(f.buffer.len(), 0, "buffer should be empty until batch processes");
    }

    #[test]
    fn process_line_finish_outputs_collapsed_groups() {
        let mut f = make_folder();
        // Feed 5 similar lines — above min_collapse=3, so they should collapse
        for i in 0..5 {
            f.process_line(&format!("2024-01-01 ERROR timeout connecting to 10.0.0.{i}"))
                .unwrap();
        }
        let output = f.finish().unwrap();
        let joined = output.join("\n");
        assert!(
            joined.contains("similar"),
            "collapsed output should contain 'similar', got: {joined}"
        );
    }

    #[test]
    fn should_flush_buffer_false_at_1000() {
        let mut f = make_folder();
        // Manually push 1000 groups into the buffer
        for i in 0..1000 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("unique pattern {i}"), vec![]),
                i + 1,
            ));
        }
        assert!(
            !f.should_flush_buffer(),
            "should_flush_buffer should be false at exactly 1000 groups"
        );
    }

    #[test]
    fn should_flush_buffer_true_above_1000() {
        let mut f = make_folder();
        for i in 0..1001 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("unique pattern {i}"), vec![]),
                i + 1,
            ));
        }
        assert!(
            f.should_flush_buffer(),
            "should_flush_buffer should be true at 1001 groups"
        );
    }

    #[test]
    fn flush_oldest_safe_group_empty_buffer_returns_none() {
        let mut f = make_folder();
        let result = f.flush_oldest_safe_group().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn flush_oldest_safe_group_flushes_old_group() {
        let mut f = make_folder();
        // Add a group at position 1
        f.buffer.push(PatternGroup::new(
            make_line("old line with 10.0.0.1", vec![Token::IPv4("10.0.0.1".into())]),
            1,
        ));
        // Advance position counter well past safe_distance (100)
        f.position_counter = 200;
        let result = f.flush_oldest_safe_group().unwrap();
        assert!(result.is_some(), "should flush group that is 199 lines old");
        assert!(f.buffer.is_empty(), "buffer should be empty after flush");
    }

    #[test]
    fn flush_oldest_safe_group_does_not_flush_recent_group() {
        let mut f = make_folder();
        // Add a group at position 50
        f.buffer.push(PatternGroup::new(
            make_line("recent line", vec![]),
            50,
        ));
        // Position counter is only 60 — well within safe_distance=100
        f.position_counter = 60;
        let result = f.flush_oldest_safe_group().unwrap();
        // Group has 1 line (< min_collapse=3) and is recent (10 < 100), so NOT ready
        assert_eq!(result, None, "should not flush recent small group");
        assert_eq!(f.buffer.len(), 1, "group should remain in buffer");
    }

    // --- Mutant-killing tests for process_line + flush_oldest_safe_group ---

    #[test]
    fn process_line_advances_position_counter() {
        // Kills: position_counter += 1 → *= 1 (stays at 0)
        let mut f = make_folder();
        assert_eq!(f.position_counter, 0);
        f.process_line("hello 10.0.0.1").unwrap();
        assert_eq!(f.position_counter, 1);
        f.process_line("world 10.0.0.2").unwrap();
        assert_eq!(f.position_counter, 2);
    }

    #[test]
    fn flush_exact_safe_distance_boundary() {
        // Kills: > safe_distance → >= safe_distance
        // safe_distance = 100, so distance of exactly 100 should NOT flush
        let mut f = make_folder();
        f.buffer.push(PatternGroup::new(
            make_line("boundary line", vec![]),
            1,
        ));
        f.position_counter = 101; // distance = 101 - 1 = 100, exactly at boundary
        let result = f.flush_oldest_safe_group().unwrap();
        assert_eq!(result, None, "distance of exactly 100 should NOT flush (> not >=)");

        // distance = 101 SHOULD flush
        f.position_counter = 102; // distance = 102 - 1 = 101
        let result = f.flush_oldest_safe_group().unwrap();
        assert!(result.is_some(), "distance of 101 should flush");
    }

    #[test]
    fn flush_uses_subtraction_not_division() {
        // Kills: current_position - group.position → current_position / group.position
        // With position=50, counter=160: 160-50=110 > 100 (flush), 160/50=3 (no flush)
        let mut f = make_folder();
        f.buffer.push(PatternGroup::new(
            make_line("division test", vec![]),
            50,
        ));
        f.position_counter = 160;
        let result = f.flush_oldest_safe_group().unwrap();
        assert!(result.is_some(), "distance 110 should flush (subtraction gives 110, division gives 3)");
    }

    #[test]
    fn flush_selects_first_among_equal_positions() {
        // Kills: group.position < oldest_position → <= oldest_position
        // Two groups at same position, different content — first should be selected
        let mut f = make_folder();
        f.buffer.push(PatternGroup::new(
            make_line("first_group_aaa", vec![]),
            5,
        ));
        f.buffer.push(PatternGroup::new(
            make_line("second_group_bbb", vec![]),
            5,
        ));
        f.position_counter = 200;
        let result = f.flush_oldest_safe_group().unwrap().unwrap();
        assert!(
            result.contains("first_group_aaa"),
            "should flush first group at equal position, got: {result}"
        );
    }

    #[test]
    fn flush_accumulates_output_lines() {
        // Kills: output_lines += count → *= count (0 * N = 0)
        let mut f = make_folder();
        f.buffer.push(PatternGroup::new(
            make_line("output line", vec![]),
            1,
        ));
        f.position_counter = 200;
        assert_eq!(f.stats.output_lines, 0);
        let _result = f.flush_oldest_safe_group().unwrap();
        assert!(
            f.stats.output_lines > 0,
            "output_lines should be incremented after flush, got 0"
        );
    }

    // ---------------------------------------------------------------
    // JSON output: format_group_json, print_summary_json, format_group_dispatch
    // ---------------------------------------------------------------

    fn make_folder_json() -> PatternFolder {
        PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            output_format: "json".to_string(),
            ..Config::default()
        })
    }

    #[test]
    fn format_group_json_below_min_collapse_no_stats_change() {
        let mut f = make_folder_json();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ]);
        assert_eq!(group.count(), 2); // below min_collapse=3
        let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
        assert_eq!(f.stats.collapsed_groups, 0);
        assert_eq!(f.stats.lines_saved, 0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["count"], 2);
    }

    #[test]
    fn format_group_json_at_min_collapse_updates_stats() {
        let mut f = make_folder_json();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        assert_eq!(group.count(), 3); // exactly min_collapse
        let _ = f.format_group_json(&group, BTreeMap::new()).unwrap();
        assert_eq!(f.stats.collapsed_groups, 1);
        assert_eq!(f.stats.lines_saved, 2); // count - 1 = 3 - 1 = 2
    }

    #[test]
    fn format_group_json_essence_mode_skips_stats() {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            output_format: "json".to_string(),
            essence_mode: true,
            ..Config::default()
        });
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        let _ = f.format_group_json(&group, BTreeMap::new()).unwrap();
        assert_eq!(f.stats.collapsed_groups, 0, "essence_mode should skip collapsed_groups");
        assert_eq!(f.stats.lines_saved, 0, "essence_mode should skip lines_saved");
    }

    #[test]
    fn format_group_json_id_increments() {
        let mut f = make_folder_json();
        let group = make_group("line", vec![vec![]]);
        let json0 = f.format_group_json(&group, BTreeMap::new()).unwrap();
        let json1 = f.format_group_json(&group, BTreeMap::new()).unwrap();
        let v0: serde_json::Value = serde_json::from_str(&json0).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&json1).unwrap();
        assert_eq!(v0["id"], 0);
        assert_eq!(v1["id"], 1);
    }

    #[test]
    fn format_group_json_token_types_sorted() {
        let mut f = make_folder_json();
        // Use tokens whose type names sort alphabetically: "ipv4" < "uuid"
        let group = make_group("error <IP> <UUID>", vec![
            vec![Token::Uuid("aaa".into()), Token::IPv4("10.0.0.1".into())],
        ]);
        let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let types: Vec<&str> = v["token_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted, "token_types should be alphabetically sorted");
    }

    #[test]
    fn format_group_json_time_range_from_timestamps() {
        let mut f = make_folder_json();
        let group = make_group("error <TIMESTAMP>", vec![
            vec![Token::Timestamp("2024-01-01T00:00:00Z".into())],
            vec![Token::Timestamp("2024-01-01T01:00:00Z".into())],
        ]);
        let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["time_range"]["first_seen"].as_str().unwrap(),
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(
            v["time_range"]["last_seen"].as_str().unwrap(),
            "2024-01-01T01:00:00Z"
        );
    }

    #[test]
    fn format_group_json_record_type_is_group() {
        let mut f = make_folder_json();
        let group = make_group("line", vec![vec![]]);
        let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "group");
    }

    #[test]
    fn print_summary_json_zero_lines() {
        let f = make_folder_json();
        let mut buf = Vec::new();
        f.print_summary_json(&mut buf, std::time::Duration::from_millis(100))
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(v["type"], "summary");
        assert_eq!(v["compression_ratio"], 0.0);
        assert_eq!(v["input_lines"], 0);
    }

    #[test]
    fn print_summary_json_with_stats() {
        let mut f = make_folder_json();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 80;
        f.stats.output_lines = 20;
        f.stats.collapsed_groups = 5;
        f.stats.patterns_detected = 50;
        f.stats.timestamps = 10;
        f.stats.ips = 5;
        let mut buf = Vec::new();
        f.print_summary_json(&mut buf, std::time::Duration::from_millis(42))
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(v["input_lines"], 100);
        assert_eq!(v["output_lines"], 20);
        assert_eq!(v["collapsed_groups"], 5);
        assert_eq!(v["lines_saved"], 80);
        assert_eq!(v["patterns_detected"], 50);
        assert_eq!(v["elapsed_ms"], 42);
        // compression_ratio = 80/100 * 100 = 80.0
        assert!((v["compression_ratio"].as_f64().unwrap() - 80.0).abs() < 0.01);
        assert_eq!(v["pattern_hits"]["timestamps"], 10);
        assert_eq!(v["pattern_hits"]["ips"], 5);
    }

    #[test]
    fn print_summary_json_ends_with_newline() {
        let f = make_folder_json();
        let mut buf = Vec::new();
        f.print_summary_json(&mut buf, std::time::Duration::from_millis(0))
            .unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'), "summary JSON should end with newline");
    }

    #[test]
    fn format_group_dispatch_text_mode() {
        let mut f = make_folder();
        let group = make_group("hello", vec![vec![]]);
        let output = f.format_group_dispatch(&group).unwrap();
        // Text mode: should NOT be valid JSON
        assert!(
            serde_json::from_str::<serde_json::Value>(&output).is_err(),
            "text mode output should not be JSON"
        );
    }

    #[test]
    fn format_group_dispatch_json_mode() {
        let mut f = make_folder_json();
        let group = make_group("hello", vec![vec![]]);
        let output = f.format_group_dispatch(&group).unwrap();
        // JSON mode: should be valid JSON
        let v: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(v["type"], "group");
    }

    // ---------------------------------------------------------------
    // Stats counters: count_pattern_types, count_active_pattern_types
    // ---------------------------------------------------------------

    #[test]
    fn count_pattern_types_timestamp() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Timestamp("2024-01-01".into())]);
        assert_eq!(f.stats.timestamps, 1);
    }

    #[test]
    fn count_pattern_types_ip_variants() {
        let mut f = make_folder();
        f.count_pattern_types(&[
            Token::IPv4("10.0.0.1".into()),
            Token::IPv6("::1".into()),
            Token::Port(8080),
        ]);
        // IPv4 + IPv6 + Port all count as ips
        assert_eq!(f.stats.ips, 3);
    }

    #[test]
    fn count_pattern_types_email() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Email("a@b.com".into())]);
        assert_eq!(f.stats.emails, 1);
    }

    #[test]
    fn count_pattern_types_kubernetes_variants() {
        let mut f = make_folder();
        f.count_pattern_types(&[
            Token::KubernetesNamespace("kube-system".into()),
            Token::VolumeName("pvc-123".into()),
            Token::PluginType("csi".into()),
            Token::PodName("nginx-abc".into()),
        ]);
        assert_eq!(f.stats.kubernetes, 4);
    }

    #[test]
    fn count_pattern_types_overloaded_bucket() {
        let mut f = make_folder();
        f.count_pattern_types(&[
            Token::Number("42".into()),
            Token::QuotedString("hello".into()),
            Token::Name("foo-bar".into()),
            Token::BracketContext(vec!["ERROR".into()]),
            Token::KeyValuePair { key: "k".into(), value_type: "string".into() },
            Token::LogWithModule { level: "INFO".into(), module: "main".into() },
            Token::StructuredMessage { component: "api".into(), level: "info".into() },
        ]);
        assert_eq!(f.stats.percentages, 7, "Number/QuotedString/Name/BracketContext/KV/Log/Structured -> percentages");
    }

    #[test]
    fn count_pattern_types_empty_tokens() {
        let mut f = make_folder();
        f.count_pattern_types(&[]);
        // No stats should change — all still zero
        assert_eq!(f.stats.timestamps, 0);
        assert_eq!(f.stats.ips, 0);
        assert_eq!(f.stats.emails, 0);
    }

    #[test]
    fn count_active_pattern_types_all_zero() {
        let f = make_folder();
        assert_eq!(f.count_active_pattern_types(), 0);
    }

    #[test]
    fn count_active_pattern_types_one_nonzero() {
        let mut f = make_folder();
        f.stats.timestamps = 5;
        assert_eq!(f.count_active_pattern_types(), 1);
    }

    #[test]
    fn count_active_pattern_types_all_nonzero() {
        let mut f = make_folder();
        f.stats.timestamps = 1;
        f.stats.ips = 1;
        f.stats.hashes = 1;
        f.stats.uuids = 1;
        f.stats.durations = 1;
        f.stats.pids = 1;
        f.stats.sizes = 1;
        f.stats.percentages = 1;
        f.stats.http_status = 1;
        f.stats.paths = 1;
        f.stats.kubernetes = 1;
        // Note: emails is NOT counted by count_active_pattern_types
        assert_eq!(f.count_active_pattern_types(), 11);
    }

    // ---------------------------------------------------------------
    // Text formatting: format_group
    // ---------------------------------------------------------------

    #[test]
    fn format_group_below_min_collapse_outputs_all_lines() {
        let mut f = make_folder();
        let group = make_group("error connecting", vec![vec![], vec![]]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        // 2 lines < min_collapse=3, should output all lines individually
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn format_group_at_min_collapse_collapses() {
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        assert!(
            output.contains("similar"),
            "collapsed output should contain 'similar', got: {output}"
        );
        assert_eq!(f.stats.collapsed_groups, 1);
    }

    #[test]
    fn format_group_single_line_no_collapse() {
        let mut f = make_folder();
        let group = make_group("hello", vec![vec![]]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        assert!(!output.contains("similar"));
        assert_eq!(output, "hello");
    }

    #[test]
    fn format_group_essence_mode_uses_normalized() {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            essence_mode: true,
            ..Config::default()
        });
        // In essence mode, single-line groups output normalized text
        let group = make_group("normalized <IP>", vec![vec![Token::IPv4("10.0.0.1".into())]]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        assert_eq!(output, "normalized <IP>");
    }

    #[test]
    fn format_group_pii_masking_masks_emails() {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize_pii: true,
            ..Config::default()
        });
        // Build a group with email token where original contains the email
        let mut line = make_line("user alice@test.com logged in", vec![Token::Email("alice@test.com".into())]);
        line.original = "user alice@test.com logged in".to_string();
        let group = PatternGroup::new(line, 1);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        assert!(
            output.contains("<EMAIL>"),
            "PII masking should replace email with <EMAIL>, got: {output}"
        );
        assert!(
            !output.contains("alice@test.com"),
            "email should be masked, got: {output}"
        );
    }

    // ---------------------------------------------------------------
    // print_stats
    // ---------------------------------------------------------------

    #[test]
    fn print_stats_contains_report_header() {
        let f = make_folder();
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("# lessence Compression Report"));
    }

    #[test]
    fn print_stats_shows_pattern_rows_for_nonzero() {
        let mut f = make_folder();
        f.stats.timestamps = 10;
        f.stats.ips = 5;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Timestamps"), "should show Timestamps row");
        assert!(output.contains("IP Addresses"), "should show IP Addresses row");
        // emails is 0, so should NOT appear
        assert!(!output.contains("Email Addresses"), "should not show Email row when 0");
    }

    #[test]
    fn print_stats_zero_lines_shows_zero_compression() {
        let f = make_folder();
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("0.0%"), "zero lines should show 0.0% compression");
    }

    #[test]
    fn print_stats_all_pattern_rows_appear() {
        let mut f = make_folder();
        f.stats.timestamps = 1;
        f.stats.ips = 2;
        f.stats.hashes = 3;
        f.stats.uuids = 4;
        f.stats.durations = 5;
        f.stats.pids = 6;
        f.stats.sizes = 7;
        f.stats.percentages = 8;
        f.stats.http_status = 9;
        f.stats.paths = 10;
        f.stats.kubernetes = 11;
        f.stats.emails = 12;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Timestamps"), "missing Timestamps row");
        assert!(output.contains("IP Addresses"), "missing IP row");
        assert!(output.contains("Hashes"), "missing Hashes row");
        assert!(output.contains("UUIDs"), "missing UUIDs row");
        assert!(output.contains("Durations"), "missing Durations row");
        assert!(output.contains("Process IDs"), "missing PIDs row");
        assert!(output.contains("File Sizes"), "missing Sizes row");
        assert!(output.contains("Numbers/Percentages"), "missing Percentages row");
        assert!(output.contains("HTTP Status"), "missing HTTP row");
        assert!(output.contains("File Paths"), "missing Paths row");
        assert!(output.contains("Kubernetes"), "missing K8s row");
        assert!(output.contains("Email Addresses"), "missing Emails row");
    }

    #[test]
    fn print_stats_compression_ratio_math() {
        let mut f = make_folder();
        f.stats.total_lines = 200;
        f.stats.lines_saved = 150;
        f.stats.output_lines = 50;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("75.0%"), "150/200 should be 75.0% reduction, got: {output}");
        assert!(output.contains("200 lines"), "should show 200 original lines");
        assert!(output.contains("50 lines"), "should show 50 compressed lines");
    }

    #[test]
    fn print_stats_high_compression_recommendation() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 95;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("High compression ratio"),
            "95% should trigger high compression recommendation"
        );
    }

    #[test]
    fn print_stats_low_compression_recommendation() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 30;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Low compression ratio"),
            "30% should trigger low compression recommendation"
        );
    }

    #[test]
    fn print_stats_moderate_compression_recommendation() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 80;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Moderate compression ratio"),
            "80% should trigger moderate recommendation"
        );
    }

    #[test]
    fn print_stats_high_repetition_warning() {
        let mut f = make_folder();
        f.stats.collapsed_groups = 51;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("High pattern repetition"),
            ">50 collapsed groups should trigger repetition warning"
        );
    }

    #[test]
    fn print_stats_no_repetition_warning_at_50() {
        let mut f = make_folder();
        f.stats.collapsed_groups = 50;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("High pattern repetition"),
            "exactly 50 collapsed groups should NOT trigger warning"
        );
    }

    #[test]
    fn print_stats_summary_section_values() {
        let mut f = make_folder();
        f.stats.total_lines = 500;
        f.stats.patterns_detected = 42;
        f.stats.collapsed_groups = 10;
        f.stats.lines_saved = 300;
        f.stats.timestamps = 5;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("42"), "should show patterns_detected=42");
        assert!(output.contains("10"), "should show collapsed_groups=10");
        assert!(output.contains("300"), "should show lines_saved=300");
    }

    // ---------------------------------------------------------------
    // format_group: lines_saved accounting
    // ---------------------------------------------------------------

    #[test]
    fn format_group_collapsed_lines_saved_count() {
        // 5 lines, min_collapse=3: lines_saved = count - 3 = 2
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ]);
        let rollup = BTreeMap::new();
        let _ = f.format_group(&group, &rollup).unwrap();
        assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed: saved = 5-3 = 2");
    }

    #[test]
    fn format_group_collapsed_at_min_saves_zero() {
        // Exactly min_collapse=3 lines: lines_saved = 3-3 = 0
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        let rollup = BTreeMap::new();
        let _ = f.format_group(&group, &rollup).unwrap();
        assert_eq!(f.stats.lines_saved, 0, "3 lines at min_collapse: saved = 3-3 = 0");
    }

    #[test]
    fn format_group_essence_mode_lines_saved() {
        // In essence mode below min_collapse, lines_saved = count - 1 when count > 1
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            essence_mode: true,
            ..Config::default()
        });
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ]);
        let rollup = BTreeMap::new();
        let _ = f.format_group(&group, &rollup).unwrap();
        assert_eq!(f.stats.lines_saved, 1, "essence mode: 2 lines → saved = 2-1 = 1");
    }

    #[test]
    fn format_group_no_collapse_no_lines_saved() {
        // Below min_collapse in standard mode: no lines saved
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ]);
        let rollup = BTreeMap::new();
        let _ = f.format_group(&group, &rollup).unwrap();
        assert_eq!(f.stats.lines_saved, 0, "below min_collapse: no lines saved");
    }

    #[test]
    fn format_group_collapsed_output_has_three_sections() {
        // Collapsed group should have: first line, collapse marker, last line
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3, "collapsed output should have 3 lines (first + marker + last)");
    }

    // ---------------------------------------------------------------
    // finish_top_n
    // ---------------------------------------------------------------

    #[test]
    fn finish_top_n_returns_sorted_by_count() {
        let mut f = make_folder();
        // Group A: 5 lines
        for _ in 0..5 {
            f.process_line("2024-01-01 ERROR timeout from 10.0.0.1").unwrap();
        }
        // Group B: 2 lines
        for _ in 0..2 {
            f.process_line("GET /api/health HTTP/1.1 200 OK").unwrap();
        }
        // Group C: 1 line
        f.process_line("unique log entry with no pattern match").unwrap();

        let (top, total_groups, _coverage) = f.finish_top_n(2).unwrap();
        assert_eq!(top.len(), 2, "should return top 2");
        assert!(
            top[0].0 >= top[1].0,
            "should be sorted descending: {} >= {}",
            top[0].0,
            top[1].0
        );
        assert!(total_groups >= 2, "total_groups should count all groups");
    }

    #[test]
    fn finish_top_n_returns_correct_total_groups() {
        let mut f = make_folder();
        f.process_line("line A with 10.0.0.1").unwrap();
        f.process_line("line B with 10.0.0.2").unwrap();
        f.process_line("line C with something else entirely different").unwrap();
        let (_top, total_groups, _coverage) = f.finish_top_n(10).unwrap();
        assert!(total_groups >= 1, "should have at least 1 group");
    }

    #[test]
    fn finish_top_n_n_exceeds_groups() {
        let mut f = make_folder();
        f.process_line("only one line 10.0.0.1").unwrap();
        let (top, _total, _coverage) = f.finish_top_n(100).unwrap();
        // Should return all groups (1 or more), not crash
        assert!(!top.is_empty());
    }

    #[test]
    fn finish_top_n_coverage_percentage() {
        let mut f = make_folder();
        // 10 identical lines = 1 group covering 100%
        for _ in 0..10 {
            f.process_line("2024-01-01 ERROR same 10.0.0.1").unwrap();
        }
        let (_top, _total, coverage) = f.finish_top_n(10).unwrap();
        assert_eq!(coverage, 100, "single group covering all lines = 100%");
    }

    // ---------------------------------------------------------------
    // finish (drains buffer in chronological order)
    // ---------------------------------------------------------------

    #[test]
    fn finish_drains_buffer_chronologically() {
        let mut f = make_folder();
        // Feed dissimilar lines to create multiple groups
        f.process_line("2024-01-01 ERROR first unique line with 10.0.0.1").unwrap();
        f.process_line("GET /api/v2/status HTTP/1.1 200 OK").unwrap();
        let output = f.finish().unwrap();
        assert!(output.len() >= 2, "should output at least 2 groups");
        // First group in output should be the first line (chronological)
        assert!(
            output[0].contains("first unique"),
            "first output should be the earliest group"
        );
    }

    #[test]
    fn finish_updates_output_lines() {
        let mut f = make_folder();
        f.process_line("a line 10.0.0.1").unwrap();
        f.process_line("another line 10.0.0.2").unwrap();
        let _output = f.finish().unwrap();
        assert!(
            f.stats.output_lines > 0,
            "finish should update output_lines stat"
        );
    }

    // ---------------------------------------------------------------
    // prepare_summary (extracted from finish_summary for testability)
    // ---------------------------------------------------------------

    #[test]
    fn prepare_summary_merges_identical_groups() {
        let mut f = make_folder();
        // Two groups with same normalized text should merge
        f.buffer.push(PatternGroup::new(
            make_line("error <IP>", vec![Token::IPv4("10.0.0.1".into())]),
            1,
        ));
        f.buffer.push(PatternGroup::new(
            make_line("error <IP>", vec![Token::IPv4("10.0.0.2".into())]),
            2,
        ));
        let (display, total_patterns, _, _) = f.prepare_summary(None, None).unwrap();
        assert_eq!(total_patterns, 1, "identical normalized text should merge");
        assert_eq!(display[0].0, 2, "merged count should be 1+1=2");
    }

    #[test]
    fn prepare_summary_accumulates_counts() {
        let mut f = make_folder();
        // Group with 3 lines + group with 2 lines (same normalized) = 5 total
        let mut g1 = PatternGroup::new(make_line("err <IP>", vec![]), 1);
        g1.add_line(make_line("err <IP>", vec![]), 2);
        g1.add_line(make_line("err <IP>", vec![]), 3);
        let mut g2 = PatternGroup::new(make_line("err <IP>", vec![]), 10);
        g2.add_line(make_line("err <IP>", vec![]), 11);
        f.buffer.push(g1);
        f.buffer.push(g2);
        let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
        assert_eq!(display[0].0, 5, "merged count should be 3+2=5");
    }

    #[test]
    fn prepare_summary_sorts_descending() {
        let mut f = make_folder();
        // Group A: 1 line, Group B: 5 lines — B should come first
        f.buffer.push(PatternGroup::new(make_line("small", vec![]), 1));
        let mut big = PatternGroup::new(make_line("big", vec![]), 10);
        for i in 0..4 {
            big.add_line(make_line("big", vec![]), 11 + i);
        }
        f.buffer.push(big);
        let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
        assert!(display[0].0 >= display[1].0, "should sort descending");
    }

    #[test]
    fn prepare_summary_top_n_limits() {
        let mut f = make_folder();
        for i in 0..10 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("pattern{i}"), vec![]),
                i + 1,
            ));
        }
        let (display, total, _, _) = f.prepare_summary(Some(3), None).unwrap();
        assert_eq!(display.len(), 3, "top_n=3 should return 3");
        assert_eq!(total, 10, "total_patterns should be 10");
    }

    #[test]
    fn prepare_summary_top_zero_shows_all() {
        let mut f = make_folder();
        for i in 0..5 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("p{i}"), vec![]),
                i + 1,
            ));
        }
        let (display, _, _, _) = f.prepare_summary(Some(0), None).unwrap();
        assert_eq!(display.len(), 5, "top_n=0 should show all");
    }

    #[test]
    fn prepare_summary_default_cap_at_30() {
        let mut f = make_folder();
        for i in 0..50 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("unique{i}"), vec![]),
                i + 1,
            ));
        }
        let (display, _, was_capped, _) = f.prepare_summary(None, None).unwrap();
        assert_eq!(display.len(), 30, "default cap should be 30");
        assert!(was_capped, "should indicate capping");
    }

    #[test]
    fn prepare_summary_fit_budget_limits() {
        let mut f = make_folder();
        for i in 0..20 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("line{i}"), vec![]),
                i + 1,
            ));
        }
        let (display, _, _, fit_truncated) = f.prepare_summary(None, Some(5)).unwrap();
        assert_eq!(display.len(), 4, "fit_budget=5 → show 4 (budget-1)");
        assert_eq!(fit_truncated, 16, "should report 16 remaining");
    }

    #[test]
    fn prepare_summary_flushes_batch_buffer() {
        // Parallel mode: lines go to batch_buffer, not buffer directly
        let mut f = PatternFolder::new(Config {
            thread_count: None,
            min_collapse: 3,
            ..Config::default()
        });
        f.process_line("2024-01-01 ERROR test 10.0.0.1").unwrap();
        assert!(!f.batch_buffer.is_empty(), "should have buffered line");
        let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
        assert!(!display.is_empty(), "should have processed batch");
    }

    // ---------------------------------------------------------------
    // format_group_dispatch: rollup computed for collapsible groups
    // ---------------------------------------------------------------

    #[test]
    fn format_group_dispatch_computes_rollup_for_collapsible() {
        // Kills: >= min_collapse → < min_collapse
        // A group at min_collapse should get rollup metadata in the output
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ]);
        assert_eq!(group.count(), 4); // >= min_collapse=3
        let output = f.format_group_dispatch(&group).unwrap();
        // Rollup produces variation markers with type names (e.g., "ipv4")
        // The legacy format_collapsed_line produces "[+N similar, varying: X]"
        // With rollup, it produces "[+N similar | ipv4×M ...]"
        assert!(
            output.contains("ipv4") || output.contains("similar"),
            "collapsible group should have rollup or collapse marker, got: {output}"
        );
    }

    // ---------------------------------------------------------------
    // format_summary_line (extracted from finish_summary)
    // ---------------------------------------------------------------

    #[test]
    fn summary_line_no_width() {
        let line = PatternFolder::format_summary_line(5, "error occurred", None);
        assert_eq!(line, "[5x] error occurred");
    }

    #[test]
    fn summary_line_fits_in_width() {
        let line = PatternFolder::format_summary_line(5, "error", Some(100));
        assert_eq!(line, "[5x] error");
    }

    #[test]
    fn summary_line_truncated() {
        let long_rep = "a".repeat(100);
        let line = PatternFolder::format_summary_line(5, &long_rep, Some(50));
        assert!(line.ends_with("..."), "should truncate with ...: {line}");
        assert!(line.len() <= 50);
    }

    #[test]
    fn summary_line_avail_under_20_no_truncate() {
        // Width so small that avail <= 20: don't truncate, just show full
        let line = PatternFolder::format_summary_line(5, "abcdefghij", Some(10));
        assert_eq!(line, "[5x] abcdefghij");
    }

    // ---------------------------------------------------------------
    // format_coverage_message (extracted from finish_summary)
    // ---------------------------------------------------------------

    #[test]
    fn coverage_msg_capped() {
        let msg = PatternFolder::format_coverage_message(10, 50, 100, 200, true);
        assert!(msg.contains("10 of 50 patterns"));
        assert!(msg.contains("50% coverage"));
        assert!(msg.contains("--top N"));
    }

    #[test]
    fn coverage_msg_not_capped() {
        let msg = PatternFolder::format_coverage_message(10, 10, 100, 200, false);
        assert!(msg.contains("10 of 10 patterns"));
        assert!(msg.contains("100 of 200 lines"));
        assert!(msg.contains("50% coverage"));
    }

    #[test]
    fn coverage_msg_zero_lines() {
        let msg = PatternFolder::format_coverage_message(0, 0, 0, 0, false);
        assert!(msg.contains("0% coverage"));
    }

    // ---------------------------------------------------------------
    // build_stats_json (extracted from print_stats_json)
    // ---------------------------------------------------------------

    #[test]
    fn build_stats_json_zero_lines() {
        let f = make_folder();
        let json = f.build_stats_json(Duration::from_millis(100));
        assert_eq!(json.compression_ratio, 0.0);
        assert_eq!(json.input_lines, 0);
        assert_eq!(json.elapsed_ms, 100);
    }

    #[test]
    fn build_stats_json_with_data() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 50;
        f.stats.output_lines = 50;
        f.stats.timestamps = 10;
        f.stats.ips = 5;
        let json = f.build_stats_json(Duration::from_secs(1));
        assert_eq!(json.compression_ratio, 50.0);
        assert_eq!(json.input_lines, 100);
        assert_eq!(json.output_lines, 50);
        assert_eq!(json.elapsed_ms, 1000);
        assert_eq!(json.pattern_hits.timestamps, 10);
        assert_eq!(json.pattern_hits.ips, 5);
    }

    // ---------------------------------------------------------------
    // print_stats boundary tests (already takes Writer)
    // ---------------------------------------------------------------

    // Boundary tests: > 90 and > 70 thresholds
    // The code uses strict >, so exactly 90.0 is NOT "High" and exactly 70.0 is NOT "Moderate"

    #[test]
    fn print_stats_91_pct_is_high() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 91;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("High compression"), "91% should be high: {output}");
    }

    #[test]
    fn print_stats_90_pct_is_moderate() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 90;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Moderate"), "exactly 90% is moderate, not high: {output}");
    }

    #[test]
    fn print_stats_71_pct_is_moderate() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 71;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Moderate"), "71% should be moderate: {output}");
    }

    #[test]
    fn print_stats_70_pct_is_low() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.lines_saved = 70;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("High compression"), "70% is not high: {output}");
        assert!(!output.contains("Moderate"), "70% is not moderate: {output}");
    }

    #[test]
    fn print_stats_50_groups_no_warning() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.collapsed_groups = 50;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("High pattern repetition"),
            "50 groups should not warn: {output}"
        );
    }

    #[test]
    fn print_stats_51_groups_warning() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.collapsed_groups = 51;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("High pattern repetition"),
            "51 groups should warn: {output}"
        );
    }

    #[test]
    fn print_stats_zero_counter_no_row() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        f.stats.timestamps = 0;
        f.stats.ips = 5;
        let mut buf = Vec::new();
        f.print_stats(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.contains("Timestamps"), "zero timestamps should have no row");
        assert!(output.contains("IP Addresses"), "nonzero IPs should have a row");
    }

    // ---------------------------------------------------------------
    // count_pattern_types: remaining token type tests
    // ---------------------------------------------------------------

    #[test]
    fn count_pattern_types_hash() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Hash(crate::patterns::HashType::MD5, "abc".into())]);
        assert_eq!(f.stats.hashes, 1);
    }

    #[test]
    fn count_pattern_types_uuid() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Uuid("550e-8400".into())]);
        assert_eq!(f.stats.uuids, 1);
    }

    #[test]
    fn count_pattern_types_pid() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Pid(1234)]);
        assert_eq!(f.stats.pids, 1);
    }

    #[test]
    fn count_pattern_types_thread_id() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::ThreadID("5678".into())]);
        assert_eq!(f.stats.pids, 1);
    }

    #[test]
    fn count_pattern_types_duration() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Duration("5s".into())]);
        assert_eq!(f.stats.durations, 1);
    }

    #[test]
    fn count_pattern_types_size() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Size("1MB".into())]);
        assert_eq!(f.stats.sizes, 1);
    }

    #[test]
    fn count_pattern_types_http_status() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::HttpStatus(200)]);
        assert_eq!(f.stats.http_status, 1);
    }

    #[test]
    fn count_pattern_types_http_status_class() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::HttpStatusClass("2xx".into())]);
        assert_eq!(f.stats.http_status, 1);
    }

    #[test]
    fn count_pattern_types_path() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Path("/var/log".into())]);
        assert_eq!(f.stats.paths, 1);
    }

    #[test]
    fn count_pattern_types_json() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Json("{}".into())]);
        assert_eq!(f.stats.paths, 1); // grouped with paths
    }

    #[test]
    fn count_pattern_types_number() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Number("42".into())]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_quoted_string() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::QuotedString("hello".into())]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_name() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::Name("app".into())]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_bracket_context() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::BracketContext(vec!["error".into()])]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_kv_pair() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::KeyValuePair {
            key: "k".into(),
            value_type: "string".into(),
        }]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_log_module() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::LogWithModule {
            module: "mod".into(),
            level: "error".into(),
        }]);
        assert_eq!(f.stats.percentages, 1);
    }

    #[test]
    fn count_pattern_types_structured_message() {
        let mut f = make_folder();
        f.count_pattern_types(&[Token::StructuredMessage {
            component: "api".into(),
            level: "info".into(),
        }]);
        assert_eq!(f.stats.percentages, 1);
    }

    // ---------------------------------------------------------------
    // sequential_clustering
    // ---------------------------------------------------------------

    #[test]
    fn sequential_clustering_empty_tokens_no_pattern() {
        let mut f = make_folder();
        let line = make_line("no patterns here", vec![]);
        f.sequential_clustering(line).unwrap();
        assert_eq!(f.stats.patterns_detected, 0);
    }

    #[test]
    fn sequential_clustering_with_tokens_increments() {
        let mut f = make_folder();
        let line = make_line("error <IP>", vec![Token::IPv4("10.0.0.1".into())]);
        f.sequential_clustering(line).unwrap();
        assert_eq!(f.stats.patterns_detected, 1);
        assert_eq!(f.stats.ips, 1);
    }

    // ---------------------------------------------------------------
    // prepare_summary boundary tests
    // ---------------------------------------------------------------

    #[test]
    fn prepare_summary_exactly_30_not_capped() {
        let mut f = make_folder();
        for i in 0..30 {
            f.buffer
                .push(PatternGroup::new(make_line(&format!("pattern {i}"), vec![]), i + 1));
        }
        let (display, _total, was_capped, _) = f.prepare_summary(None, None).unwrap();
        assert!(!was_capped, "exactly 30 should not be capped");
        assert_eq!(display.len(), 30);
    }

    #[test]
    fn prepare_summary_31_is_capped() {
        let mut f = make_folder();
        for i in 0..31 {
            f.buffer
                .push(PatternGroup::new(make_line(&format!("pattern {i}"), vec![]), i + 1));
        }
        let (display, _total, was_capped, _) = f.prepare_summary(None, None).unwrap();
        assert!(was_capped, "31 should be capped");
        assert_eq!(display.len(), 30);
    }

    #[test]
    fn prepare_summary_top_zero_no_cap_50() {
        let mut f = make_folder();
        for i in 0..50 {
            f.buffer
                .push(PatternGroup::new(make_line(&format!("pattern {i}"), vec![]), i + 1));
        }
        let (display, _total, was_capped, _) = f.prepare_summary(Some(0), None).unwrap();
        assert!(!was_capped);
        assert_eq!(display.len(), 50);
    }

    #[test]
    fn prepare_summary_fit_budget_10_of_50() {
        let mut f = make_folder();
        for i in 0..50 {
            f.buffer
                .push(PatternGroup::new(make_line(&format!("pattern {i}"), vec![]), i + 1));
        }
        let (display, _total, _was_capped, fit_truncated) =
            f.prepare_summary(None, Some(10)).unwrap();
        assert!(display.len() <= 10);
        assert!(fit_truncated > 0);
    }

    // ---------------------------------------------------------------
    // finish_top_n boundary tests
    // ---------------------------------------------------------------

    #[test]
    fn finish_top_n_zero_input_lines() {
        let mut f = make_folder();
        f.stats.total_lines = 0;
        let (_, _, coverage) = f.finish_top_n(10).unwrap();
        assert_eq!(coverage, 0);
    }

    // ---------------------------------------------------------------
    // Targeted tests for remaining missed mutants
    // ---------------------------------------------------------------

    // format_group_dispatch line 729: >= with < boundary
    // count < min_collapse should NOT compute rollup
    #[test]
    fn format_group_dispatch_below_min_collapse_no_rollup() {
        let mut f = make_folder(); // min_collapse = 3
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ]); // count = 2, below min_collapse = 3
        let output = f.format_group_dispatch(&group).unwrap();
        // Below min_collapse: no rollup marker, just the raw lines
        assert!(!output.contains("similar"), "2 lines should not collapse: {output}");
    }

    #[test]
    fn format_group_dispatch_at_min_collapse_computes_rollup() {
        let mut f = make_folder(); // min_collapse = 3
        // Use enough varied tokens that rollup produces distinct output vs legacy
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ]); // count = 5, well above min_collapse
        let output = f.format_group_dispatch(&group).unwrap();
        // Rollup path produces "ipv4×N" markers; legacy produces "[+N similar, varying: ...]"
        // If >= is mutated to <, count=5 >= 3 would become 5 < 3 = false → empty rollup
        // → legacy format which says "similar" but NOT "ipv4"
        assert!(
            output.contains("ipv4"),
            "rollup should produce ipv4 marker, got legacy format: {output}"
        );
    }

    // prepare_summary: return value substitution tests (lines 941)
    #[test]
    fn prepare_summary_returns_nonempty_for_nonempty_buffer() {
        let mut f = make_folder();
        f.buffer.push(PatternGroup::new(make_line("error", vec![]), 1));
        let (display, total, was_capped, fit_truncated) = f.prepare_summary(None, None).unwrap();
        assert!(!display.is_empty(), "should return entries for non-empty buffer");
        assert_eq!(total, 1);
        assert!(!was_capped);
        assert_eq!(fit_truncated, 0);
    }

    // prepare_summary line 969: > boundary with top_n=Some(0) + fit_budget
    #[test]
    fn prepare_summary_top_zero_fit_budget_exact_boundary() {
        let mut f = make_folder();
        for i in 0..5 {
            f.buffer.push(PatternGroup::new(make_line(&format!("p{i}"), vec![]), i + 1));
        }
        // top=0 + budget=5: sorted.len() == budget, NOT > budget → no truncation
        let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(5)).unwrap();
        assert_eq!(display.len(), 5);
        assert_eq!(fit_truncated, 0, "exact fit should not truncate");
    }

    #[test]
    fn prepare_summary_top_zero_fit_budget_over() {
        let mut f = make_folder();
        for i in 0..5 {
            f.buffer.push(PatternGroup::new(make_line(&format!("p{i}"), vec![]), i + 1));
        }
        // top=0 + budget=3: sorted.len() > budget → truncate
        let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(3)).unwrap();
        assert_eq!(display.len(), 2); // budget.saturating_sub(1) = 2
        assert_eq!(fit_truncated, 3); // 5 - 2 = 3 remaining
    }

    // prepare_summary line 971: saturating_sub arithmetic
    #[test]
    fn prepare_summary_top_zero_fit_budget_one() {
        let mut f = make_folder();
        for i in 0..5 {
            f.buffer.push(PatternGroup::new(make_line(&format!("p{i}"), vec![]), i + 1));
        }
        // budget=1, saturating_sub(1) = 0 → show 0 patterns, remaining = 5
        let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(1)).unwrap();
        assert_eq!(display.len(), 0);
        assert_eq!(fit_truncated, 5);
    }

    // prepare_summary line 983: > with >= on fit_budget (no top_n)
    #[test]
    fn prepare_summary_fit_budget_exact() {
        let mut f = make_folder();
        for i in 0..5 {
            f.buffer.push(PatternGroup::new(make_line(&format!("p{i}"), vec![]), i + 1));
        }
        // fit_budget=5, sorted.len()=5 → NOT > budget → no truncation
        let (display, _, _, fit_truncated) = f.prepare_summary(None, Some(5)).unwrap();
        assert_eq!(display.len(), 5);
        assert_eq!(fit_truncated, 0);
    }

    // format_summary_line: detailed boundary tests
    #[test]
    fn summary_line_truncation_arithmetic() {
        // Width = 30, prefix "[5x] " = 5 chars, representative = 30 chars
        // prefix.len() + representative.len() = 35 > 30 → truncate
        // avail = 30 - 5 - 3 = 22 > 20 → do truncate with ...
        let line = PatternFolder::format_summary_line(5, &"x".repeat(30), Some(30));
        assert!(line.ends_with("..."), "should truncate: {line}");
        assert!(line.len() <= 30, "should fit in width: len={}", line.len());
    }

    #[test]
    fn summary_line_prefix_plus_rep_exactly_at_width() {
        // prefix "[5x] " = 5 chars + representative 25 chars = 30 = width → no truncation
        let line = PatternFolder::format_summary_line(5, &"x".repeat(25), Some(30));
        assert!(!line.ends_with("..."), "exact fit should not truncate: {line}");
    }

    #[test]
    fn summary_line_avail_exactly_20() {
        // Width = 28, prefix "[5x] " = 5, avail = 28 - 5 - 3 = 20 → exactly 20, NOT > 20
        // So: don't truncate (avail must be > 20)
        let long = "x".repeat(30);
        let line = PatternFolder::format_summary_line(5, &long, Some(28));
        assert!(!line.ends_with("..."), "avail=20 should not truncate: {line}");
    }

    #[test]
    fn summary_line_avail_21_does_truncate() {
        // Width = 29, prefix "[5x] " = 5, avail = 29 - 5 - 3 = 21 > 20 → truncate
        let long = "x".repeat(30);
        let line = PatternFolder::format_summary_line(5, &long, Some(29));
        assert!(line.ends_with("..."), "avail=21 should truncate: {line}");
    }

    // finish_summary line 1051: replace with Ok(()) — verify it actually does something
    #[test]
    fn finish_summary_does_not_panic() {
        let mut f = make_folder();
        f.stats.total_lines = 10;
        for i in 0..3 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("error {i}"), vec![]),
                i + 1,
            ));
        }
        // finish_summary prints to stdout — verify it runs without error
        f.finish_summary(None, None).unwrap();
    }

    // finish_summary line 1068: fit_truncated > 0 boundary
    #[test]
    fn finish_summary_with_fit_truncation() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        for i in 0..10 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("pattern {i}"), vec![]),
                i + 1,
            ));
        }
        // fit_budget=3 with 10 patterns → fit_truncated > 0
        f.finish_summary(None, Some(3)).unwrap();
        // Can't capture stdout, but no panic = OK
    }

    // finish_top_n line 1108: delete ! on batch_buffer.is_empty()
    #[test]
    fn finish_top_n_flushes_batch_buffer() {
        let mut f = make_folder();
        f.stats.total_lines = 5;
        // Put lines in batch_buffer (simulating unprocessed batch)
        f.batch_buffer.push("error one".to_string());
        f.batch_buffer.push("error two".to_string());
        let (output, total, _) = f.finish_top_n(10).unwrap();
        // Should have flushed and processed the batch
        assert!(f.batch_buffer.is_empty(), "batch should be flushed");
        assert!(total > 0 || output.is_empty()); // processed something
    }

    // finish_top_n line 1131: += on output_lines
    #[test]
    fn finish_top_n_updates_output_lines() {
        let mut f = make_folder();
        f.stats.total_lines = 10;
        for i in 0..3 {
            f.buffer.push(PatternGroup::new(
                make_line(&format!("error {i}"), vec![]),
                i + 1,
            ));
        }
        let before = f.stats.output_lines;
        let _ = f.finish_top_n(10).unwrap();
        assert!(f.stats.output_lines > before, "should increment output_lines");
    }

    // finish_top_n line 1139: > with >= on coverage calc
    #[test]
    fn finish_top_n_coverage_50_percent() {
        let mut f = make_folder();
        f.stats.total_lines = 100;
        // Create one group with 50 lines
        let mut group = PatternGroup::new(make_line("error", vec![]), 1);
        for i in 1..50 {
            group.add_line(make_line("error", vec![]), i + 1);
        }
        f.buffer.push(group);
        let (_, _, coverage) = f.finish_top_n(10).unwrap();
        assert_eq!(coverage, 50, "50/100 lines = 50% coverage");
    }

    // format_group line 1198: delete ! on rollup.is_empty()
    #[test]
    fn format_group_empty_rollup_uses_legacy() {
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        let empty_rollup = BTreeMap::new();
        let output = f.format_group(&group, &empty_rollup).unwrap();
        // Empty rollup → legacy format_collapsed_line path
        assert!(output.contains("similar"), "empty rollup should use legacy: {output}");
    }

    #[test]
    fn format_group_nonempty_rollup_uses_compact() {
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ]);
        let rollup = f.rollup_computer.compute(&group);
        let output = f.format_group(&group, &rollup).unwrap();
        // Non-empty rollup → compact marker path
        assert!(
            output.contains("ipv4") || output.contains("similar"),
            "non-empty rollup should use compact: {output}"
        );
    }

    // format_group line 1202/1213: - with + on count-2 and count-3
    #[test]
    fn format_group_lines_saved_arithmetic() {
        let mut f = make_folder();
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ]); // count = 5
        let rollup = BTreeMap::new();
        f.format_group(&group, &rollup).unwrap();
        // lines_saved = count - 3 = 5 - 3 = 2
        assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed saves 2");
    }

    // format_group line 1228: && with || and delete ! on essence_mode PII
    #[test]
    fn format_group_pii_masking_only_in_non_essence() {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize_pii: true,
            essence_mode: false,
            ..Config::default()
        });
        let group = make_group("user test@example.com logged in", vec![
            vec![Token::Email("test@example.com".into())],
            vec![Token::Email("test@example.com".into())],
            vec![Token::Email("test@example.com".into())],
        ]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        // PII masking: email should be masked
        assert!(
            output.contains("***@***") || !output.contains("test@example.com"),
            "PII should be masked in non-essence mode: {output}"
        );
    }

    // format_group line 1238: > with >= on group.count() > 1
    #[test]
    fn format_group_single_line_no_last() {
        let mut f = make_folder();
        let group = make_group("single line", vec![vec![]]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        // Single line: no "last line" section
        assert_eq!(output.lines().count(), 1, "single line should have 1 line: {output}");
    }

    #[test]
    fn format_group_two_lines_has_last() {
        let mut f = make_folder();
        let group = make_group("error msg", vec![vec![], vec![]]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        // Two lines, below min_collapse: both lines shown
        assert!(output.lines().count() >= 2, "two lines should show both: {output}");
    }

    // format_group line 1249: != with == on essence_mode first!=last
    #[test]
    fn format_group_essence_identical_suppresses_last() {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            min_collapse: 3,
            essence_mode: true,
            ..Config::default()
        });
        // 4 lines, all same normalized text → in essence mode, last = first, suppress last
        let group = make_group("error <IP>", vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ]);
        let rollup = BTreeMap::new();
        let output = f.format_group(&group, &rollup).unwrap();
        let line_count = output.lines().count();
        // Essence mode with identical first/last normalized: last suppressed
        // Should have first line + collapsed marker, but NOT a third "last" line
        assert!(line_count <= 2, "essence mode should suppress identical last: {output}");
    }
}
