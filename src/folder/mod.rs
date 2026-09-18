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
use crate::patterns::{LogLine, StatsBucket, Token, word_spans};

/// Apply PII masking to original text: email addresses (from detected
/// tokens) become `<EMAIL>`, then credential-class values (assignments,
/// JWTs, provider keys — see `mask_credentials` below) are masked.
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
    Sanitizer::legacy().mask_line(original, tokens)
}

use crate::sanitize::{CREDENTIAL_ASSIGNMENT, JWT, PROVIDER_KEY, Sanitizer};

/// Mask credential-class values: assignments to credential-named keys,
/// JWTs, and provider-prefixed API keys. Runs as part of the single
/// --sanitize-pii pass (all callers gate on the flag), so every output
/// mode and field masks identically. Assignment masking runs first so
/// `token: eyJ...` collapses to one `<SECRET>` rather than a nested mask.
/// Shortest value the assignment locator will call a credential. The
/// harvest scrubber's floor: below it the match is prose, not a secret.
const MIN_CREDENTIAL_VALUE: usize = 6;

/// Is the value of a `key: value` match a credential, or is the match prose
/// that happens to contain a credential word? Masking may over-match — it
/// hides what it is unsure of — but an invention *rewrites* the words it
/// touches, so `failed to fetch token: Post "https://…": read tcp …` has to
/// come back with `Post` and `read` intact. Two shape rules: a credential
/// value is at least six characters, and a key reached through a `/` is a
/// URL path segment (`…/serviceaccounts/cilium/token\": net/http: …`), not
/// an assignment.
fn is_credential_value(text: &str, match_start: usize, value: &str) -> bool {
    let bare = value
        .strip_prefix(['"', '\''])
        .and_then(|v| v.strip_suffix(['"', '\'']))
        .unwrap_or(value);
    bare.len() >= MIN_CREDENTIAL_VALUE && !text[..match_start].ends_with('/')
}

/// Byte ranges of the *values* the credential locators find: the value of
/// a credential-named assignment, and whole JWT / provider-key matches.
/// `mask_credentials` replaces these with a marker; `--anonymize` invents a
/// same-shape value for them instead, off the same three patterns — with the
/// prose guard above, which masking does not need and inventions do.
pub(crate) fn credential_spans(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut spans: Vec<std::ops::Range<usize>> = CREDENTIAL_ASSIGNMENT
        .captures_iter(text)
        .filter(|c| {
            let whole = c.get(0).expect("group 0 always present on a match");
            let value = c.get(2).expect("group 2 always present on a match");
            is_credential_value(text, whole.start(), value.as_str())
        })
        .filter_map(|c| c.get(2).map(|m| m.range()))
        .collect();
    for re in [&*JWT, &*PROVIDER_KEY] {
        spans.extend(re.find_iter(text).map(|m| m.range()));
    }
    spans
}

#[cfg(test)]
fn mask_credentials(text: &str) -> String {
    Sanitizer::legacy().mask_text(text)
}

#[derive(Debug)]
struct PatternGroup {
    lines: Vec<LogLine>,
    /// What is shown for the group. Starts as the first line's normalized
    /// form; a merged member that differs in a plain word turns that word
    /// into `<VARIES>`, so the template never claims a word half the
    /// members lack (lessence-098).
    template: String,
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
    /// --explain only: the existing group this line scored highest against
    /// before founding its own, or `None` when the buffer was empty.
    nearest: Option<Nearest>,
    /// --distill only: the input line number of every member, in member
    /// order (parallel to `lines`). Empty in every other mode, so the
    /// per-line cost is not paid unless a distillation asked for it.
    member_line_nos: Vec<usize>,
    /// True member count. Equals `lines.len()` for a group that has never
    /// been evicted from the live buffer (the common case). A group that
    /// *has* been evicted (lessence-940) keeps accumulating this field
    /// after `lines` is truncated down to just its first and last member —
    /// `count()` reads this, never `lines.len()`, so every caller sees the
    /// true total regardless of what is physically retained.
    count: usize,
    /// Set once this group has passed through eviction: the bounded rollup
    /// accumulator that survives in place of the full member list. `None`
    /// for a group still fully materialized in `lines`.
    retained: Option<RetainedState>,
}

/// Rollup accumulator for a group that has been evicted from the live
/// buffer but keeps its identity (lessence-940): seeded once by scanning
/// every member the group had at eviction time (`RollupComputer::seed`,
/// identical arithmetic to a normal flush), then extended one rejoining
/// member at a time (`RollupComputer::accumulate_tokens` /
/// `accumulate_retained_varies`). Unequal-length normalized forms are
/// counted under `distinct_cap` and aligned once against the final template.
/// Finalised into a `GroupRollup` exactly once, at actual emission.
#[derive(Debug, Default)]
struct RetainedState {
    per_type: BTreeMap<&'static str, (Accumulator, bool)>,
    varies: HashMap<String, usize>,
    varies_capped: bool,
    /// Equal-length members align positionally, even as literals widen.
    positional_members: usize,
    /// Unequal-length members need LCS alignment against the final template.
    /// Count their normalized forms, bounded by the same distinct cap.
    realign: BTreeMap<String, usize>,
    realign_capped: bool,
}

/// First whitespace token at which two normalized lines disagree. Tokenizes
/// the way similarity does (`split_whitespace`), so the answer names the
/// token the score actually tripped over.
fn first_diff(line: &LogLine, rep: &LogLine) -> Option<FirstDiff> {
    let ours = line.normalized.split_whitespace();
    let theirs = rep.normalized.split_whitespace();
    for (a, b) in ours.zip(theirs) {
        if a != b {
            let at = a.as_ptr() as usize - line.normalized.as_ptr() as usize;
            return Some(FirstDiff {
                ours: a.to_string(),
                theirs: b.to_string(),
                at,
            });
        }
    }
    // One is a prefix of the other: the diff is the first surplus token.
    let ours: Vec<&str> = line.normalized.split_whitespace().collect();
    let theirs: Vec<&str> = rep.normalized.split_whitespace().collect();
    match ours.len().cmp(&theirs.len()) {
        std::cmp::Ordering::Greater => {
            let a = ours[theirs.len()];
            Some(FirstDiff {
                ours: a.to_string(),
                theirs: String::new(),
                at: a.as_ptr() as usize - line.normalized.as_ptr() as usize,
            })
        }
        std::cmp::Ordering::Less => Some(FirstDiff {
            ours: String::new(),
            theirs: theirs[ours.len()].to_string(),
            at: line.normalized.len(),
        }),
        std::cmp::Ordering::Equal => None,
    }
}

/// Why a line founded a new group instead of joining one (`--explain`).
#[derive(Debug, Clone, Serialize)]
pub(super) struct Nearest {
    /// `first.line_no` of the nearest group — the one key that is fixed the
    /// moment a group is founded. JSON `id` is assigned at flush time, and
    /// groups flush out of buffer order, so it is not knowable here.
    pub group_line_no: usize,
    /// `similarity_score` against that group's representative, in percent.
    pub score: f64,
    /// The two lines carry different anchors (endpoint, device), so they were
    /// never scored: anchors are matched, not scored. Present only when true,
    /// and it explains a high `score` that still did not join.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub anchor_mismatch: bool,
    /// The first token pair that differs, in line order. `None` when the two
    /// lines tokenize identically but still failed (anchor mismatch).
    pub first_diff: Option<FirstDiff>,
}

/// One diverging token pair, plus its byte offset in the new line.
#[derive(Debug, Clone, Serialize)]
pub(super) struct FirstDiff {
    pub ours: String,
    pub theirs: String,
    pub at: usize,
}

impl PatternGroup {
    fn new(line: LogLine, position: usize) -> Self {
        Self::new_at(line, position, LineLocation::new(SourceId::STDIN, position))
    }

    fn new_at(line: LogLine, position: usize, location: LineLocation) -> Self {
        Self {
            template: line.normalized.clone(),
            lines: vec![line],
            position,
            first_line_no: location.line_no,
            last_line_no: location.line_no,
            first_source_id: location.source_id,
            last_source_id: location.source_id,
            nearest: None,
            member_line_nos: Vec::new(),
            count: 1,
            retained: None,
        }
    }

    fn add_line(&mut self, line: LogLine, line_no: usize) {
        self.add_line_at(line, LineLocation::new(SourceId::STDIN, line_no));
    }

    fn add_line_at(&mut self, line: LogLine, location: LineLocation) {
        if line.hash != self.lines[0].hash {
            self.mark_varying_words(&line.normalized);
        }
        self.lines.push(line);
        self.last_line_no = location.line_no;
        self.last_source_id = location.source_id;
        self.count += 1;
    }

    /// Rejoin a member into a group that has already been evicted from the
    /// live buffer. A similar member can introduce a new varying slot:
    /// its former literal held for every earlier positional member, so seed
    /// that value with their count before adding the new member (lessence-3ck).
    /// `lines` stays at its truncated [first, last] shape.
    fn retained_rejoin(
        &mut self,
        line: LogLine,
        location: LineLocation,
        rollup_computer: &RollupComputer,
    ) {
        if line.hash != self.first().hash {
            let edits = varying_spans(&self.template, &line.normalized);
            if let Some(state) = &mut self.retained {
                rollup_computer.accumulate_new_varies(&self.template, &edits, state);
            }
            for (at, len) in edits.into_iter().rev() {
                self.template.replace_range(at..at + len, VARIES_MARK);
            }
        }
        self.count += 1;
        self.last_line_no = location.line_no;
        self.last_source_id = location.source_id;
        if let Some(state) = &mut self.retained {
            rollup_computer.accumulate_tokens(std::slice::from_ref(&line), &mut state.per_type);
            rollup_computer.accumulate_retained_varies(&line, &self.template, state);
        }
        if self.lines.len() < 2 {
            self.lines.push(line);
        } else {
            self.lines[1] = line;
        }
    }

    /// Fold another group into this one at render time (lessence-682).
    /// Only ever called for two groups whose templates and anchors are
    /// identical, so every member of `other` already satisfies this
    /// group's claim and the template needs no re-marking. Whichever of
    /// the two holds the full member list keeps it; as soon as either has
    /// been through eviction the merged group carries an accumulator
    /// instead, extended from the other's members or accumulator without
    /// a rescan.
    fn absorb(&mut self, other: PatternGroup, rollup_computer: &RollupComputer) {
        debug_assert_eq!(self.template, other.template);
        self.count += other.count;
        let other_is_later = other.last_line_no > self.last_line_no
            || (other.last_line_no == self.last_line_no && other.position > self.position);
        if other_is_later {
            self.last_line_no = other.last_line_no;
            self.last_source_id = other.last_source_id;
        }
        self.member_line_nos.extend(other.member_line_nos);

        if self.retained.is_none() && other.retained.is_none() {
            // Both fully materialized: one member list, with the true last
            // member kept at the end so `last()` stays honest.
            let own_last = self.lines.pop().unwrap();
            let mut other_lines = other.lines;
            if other_is_later {
                self.lines.push(own_last);
                self.lines.append(&mut other_lines);
            } else {
                self.lines.append(&mut other_lines);
                self.lines.push(own_last);
            }
            return;
        }

        if self.retained.is_none() {
            self.retained = Some(rollup_computer.seed(self));
        }
        let state = self.retained.as_mut().expect("seeded above");
        if let Some(from) = other.retained {
            rollup_computer.merge_retained(state, from);
        } else {
            rollup_computer.accumulate_tokens(&other.lines, &mut state.per_type);
            for line in &other.lines {
                rollup_computer.accumulate_retained_varies(line, &self.template, state);
            }
        }
        let first = self.lines[0].clone();
        let last = if other_is_later {
            other.lines.last().cloned()
        } else if self.lines.len() > 1 {
            self.lines.last().cloned()
        } else {
            None
        };
        self.lines = match last {
            Some(last) if self.count > 1 => vec![first, last],
            _ => vec![first],
        };
    }

    /// A member that differs from the template at some word — `Timeout`
    /// where the first line said `Unreachable`, a bare `board` where it said
    /// `<FQDN>`, `-sdown` read as `<FLAG>` where it said `+sdown` — makes
    /// that word `<VARIES>`: the template must hold for every member, and a
    /// placeholder on one side is a claim the other side breaks. A shared
    /// `key=` / `"key":` prefix is kept (`msg=<VARIES>`), so the field name
    /// stays on the line. Members with a different word count are aligned
    /// by longest common subsequence; template words the member lacks vary
    /// too, since the template cannot show an absence any other way.
    fn mark_varying_words(&mut self, member: &str) {
        let edits = varying_spans(&self.template, member);
        for (at, len) in edits.into_iter().rev() {
            self.template.replace_range(at..at + len, "<VARIES>");
        }
    }

    /// The shown form of the group: the first line's template with
    /// `<VARIES>` wherever members disagreed in a plain word.
    pub(super) fn template(&self) -> &str {
        &self.template
    }

    fn should_collapse(&self, min_collapse: usize) -> bool {
        self.count() >= min_collapse
    }

    fn first(&self) -> &LogLine {
        &self.lines[0]
    }

    fn last(&self) -> &LogLine {
        &self.lines[self.lines.len() - 1]
    }

    fn count(&self) -> usize {
        self.count
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
    /// `--sanitize` / `--sanitize-pii`: the masker every rendered field
    /// passes through, or `None` when nothing is masked.
    pub(super) sanitizer: Option<Sanitizer>,
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
    /// --distill: input line numbers to keep, appended group by group as
    /// groups flush. Unordered across groups; `src/distill.rs` sorts.
    distill_kept: Vec<usize>,
    /// --distill: one template per flushed group — the input side of the
    /// template-set contract check.
    distill_templates: Vec<String>,
    /// --distill only: per-template clock spans, combined across evictions.
    distill_rates: crate::distill::rates::Rates,
    /// Groups evicted from the live buffer that keep their identity
    /// instead of being emitted immediately (lessence-940): a later line
    /// whose founding hash matches rejoins here instead of founding a
    /// fresh group. Keyed the same way `group_index` is — a hash present
    /// in one map is never present in the other. Never populated in
    /// --distill mode (distillation needs every member's raw line, which
    /// eviction would discard) or in the ranked modes (they never evict).
    /// Drained and emitted once each, at `finish()`.
    retained: ahash::AHashMap<u64, PatternGroup>,
    retained_index: retained_index::RetainedIndex,
    /// How many times a group could not be retained because
    /// `RETAINED_TEMPLATE_CAP` was already full when it evicted — it was
    /// emitted immediately instead, exactly as before this feature, and so
    /// remains fragmentable if the same template reappears later. Declared
    /// in the JSON completeness record rather than silently dropped.
    json_retention_cap_hits: usize,
}

/// Outcome of `PatternFolder::retain_evicted_group`. Not a `Result` — a
/// declined group is the routine fallback path (--distill, or the
/// retention cap), not an error, and clippy's `result_large_err` lint
/// correctly flags a ~270-byte `PatternGroup` in an `Err` variant. This
/// eviction-time path is cold relative to per-line clustering, so the size
/// difference between variants is not worth boxing for.
#[allow(clippy::large_enum_variant)]
enum Retention {
    /// Moved into `self.retained`; nothing to emit now.
    Kept,
    /// Not retained; the caller emits it immediately, exactly as before
    /// this feature.
    Declined(PatternGroup),
}

/// Upper bound on distinct templates held in `PatternFolder::retained` at
/// once. Past this, a newly-evicted group is emitted immediately instead
/// of retained — the same behaviour as before this feature — rather than
/// growing the map without limit. Chosen well above the distinct-template
/// count of every corpus this project measures against (~2,200 on the
/// largest), so the cap is a genuine backstop, not an expected ceiling.
const RETAINED_TEMPLATE_CAP: usize = 16_384;

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
    pub cpu_quantities: usize,
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
    pub macs: usize,

    // Briefing collectors (lessence-xxz). Per-line format/level counters and
    // the run's timestamp span are updated on the sequential path only
    // (never inside the rayon closure); the template map is updated wherever
    // a group is finalised.
    pub format_json: usize,
    pub format_logfmt: usize,
    pub format_plain: usize,
    pub level_fatal: usize,
    pub level_error: usize,
    pub level_warn: usize,
    pub level_info: usize,
    pub level_debug: usize,
    pub level_trace: usize,
    pub level_lines_with_level: usize,
    pub span_first: Option<String>,
    pub span_last: Option<String>,
    pub template_counts: crate::briefing::TemplateCounts,
    pub histogram: crate::briefing::HistogramBuilder,
    /// Distinct-value cardinality per token class (lessence-nn3), keyed by
    /// the same `StatsBucket` as `bump`. One estimator per class that has
    /// ever seen a token; classes that never occur are simply absent.
    pub(crate) cardinality: ahash::AHashMap<StatsBucket, crate::briefing::CardinalityEstimator>,
}

impl FoldingStats {
    fn compression_ratio(&self) -> f64 {
        if self.total_lines == 0 {
            0.0
        } else {
            self.lines_saved as f64 / self.total_lines as f64 * 100.0
        }
    }

    /// Classify one raw input line's format and severity for the briefing,
    /// from its already-detected tokens (falling back to a bounded raw-byte
    /// scan for level only when no token answers it — see
    /// `crate::briefing::level_from_tokens`). Called once per line on the
    /// sequential path, regardless of thread mode, after tokens are known
    /// (so alongside `count_pattern_types`/`record_span`, not before them).
    fn record_briefing_line(&mut self, tokens: &[Token], line: &str) {
        let format = crate::briefing::format_from_line(tokens, line);
        let level = crate::briefing::level_from_tokens(tokens, line);
        match format {
            crate::briefing::FormatClass::Json => self.format_json += 1,
            crate::briefing::FormatClass::Logfmt => self.format_logfmt += 1,
            crate::briefing::FormatClass::Plain => self.format_plain += 1,
        }
        if let Some(level) = level {
            self.level_lines_with_level += 1;
            match level {
                crate::briefing::Level::Fatal => self.level_fatal += 1,
                crate::briefing::Level::Error => self.level_error += 1,
                crate::briefing::Level::Warn => self.level_warn += 1,
                crate::briefing::Level::Info => self.level_info += 1,
                crate::briefing::Level::Debug => self.level_debug += 1,
                crate::briefing::Level::Trace => self.level_trace += 1,
            }
        }
    }

    /// Extend the run's timestamp span with one line's tokens. Called on
    /// every sequential-clustering path (single-thread and post-batch),
    /// each of which sees lines in file order.
    fn record_span(&mut self, tokens: &[Token]) {
        if let Some(ts) = first_timestamp_in(tokens) {
            if self.span_first.is_none() {
                self.span_first = Some(ts.clone());
            }
            if let Some(epoch) = crate::briefing::epoch_seconds(&ts) {
                self.histogram.record(epoch);
            }
            self.span_last = Some(ts);
        }
    }

    /// Every token class as (briefing field name, count), for the
    /// briefing's `tokens` list. Distinct from `pattern_counters`'s
    /// human-readable labels — these are the stable machine names the
    /// bead specifies.
    fn token_classes(&self) -> [(&'static str, StatsBucket, usize); 23] {
        [
            ("timestamps", StatsBucket::Timestamps, self.timestamps),
            ("ips", StatsBucket::Ips, self.ips),
            ("ports", StatsBucket::Ports, self.ports),
            ("fqdns", StatsBucket::Fqdns, self.fqdns),
            ("hashes", StatsBucket::Hashes, self.hashes),
            ("uuids", StatsBucket::Uuids, self.uuids),
            ("pids", StatsBucket::Pids, self.pids),
            ("paths", StatsBucket::Paths, self.paths),
            ("json", StatsBucket::Json, self.json),
            ("durations", StatsBucket::Durations, self.durations),
            (
                "cpu_quantities",
                StatsBucket::CpuQuantities,
                self.cpu_quantities,
            ),
            ("sizes", StatsBucket::Sizes, self.sizes),
            ("percentages", StatsBucket::Percentages, self.percentages),
            (
                "quoted_strings",
                StatsBucket::QuotedStrings,
                self.quoted_strings,
            ),
            ("names", StatsBucket::Names, self.names),
            ("brackets", StatsBucket::Brackets, self.brackets),
            ("key_values", StatsBucket::KeyValues, self.key_values),
            ("log_modules", StatsBucket::LogModules, self.log_modules),
            ("structured", StatsBucket::Structured, self.structured),
            ("kubernetes", StatsBucket::Kubernetes, self.kubernetes),
            ("emails", StatsBucket::Emails, self.emails),
            ("macs", StatsBucket::Macs, self.macs),
            ("http_status", StatsBucket::HttpStatus, self.http_status),
        ]
    }

    /// Distinct-value count and exactness for one token class, from the
    /// per-class cardinality estimator. `(0, true)` for a class that never
    /// occurred — no estimator was ever created for it.
    fn cardinality_for(&self, bucket: StatsBucket) -> (u64, bool) {
        self.cardinality
            .get(&bucket)
            .map_or((0, true), |c| (c.distinct(), c.is_exact()))
    }
    /// Route one detected token into its distribution counter. The
    /// token-kind → bucket mapping is a fact of the token taxonomy
    /// (`Token::facts().stats_bucket`); this is the bucket → field side.
    fn bump(&mut self, bucket: StatsBucket) {
        match bucket {
            StatsBucket::Timestamps => self.timestamps += 1,
            StatsBucket::Ips => self.ips += 1,
            StatsBucket::Ports => self.ports += 1,
            StatsBucket::Fqdns => self.fqdns += 1,
            StatsBucket::Hashes => self.hashes += 1,
            StatsBucket::Uuids => self.uuids += 1,
            StatsBucket::Pids => self.pids += 1,
            StatsBucket::Durations => self.durations += 1,
            StatsBucket::CpuQuantities => self.cpu_quantities += 1,
            StatsBucket::HttpStatus => self.http_status += 1,
            StatsBucket::Sizes => self.sizes += 1,
            StatsBucket::Percentages => self.percentages += 1,
            StatsBucket::Paths => self.paths += 1,
            StatsBucket::Json => self.json += 1,
            StatsBucket::QuotedStrings => self.quoted_strings += 1,
            StatsBucket::Names => self.names += 1,
            StatsBucket::Brackets => self.brackets += 1,
            StatsBucket::KeyValues => self.key_values += 1,
            StatsBucket::LogModules => self.log_modules += 1,
            StatsBucket::Structured => self.structured += 1,
            StatsBucket::Kubernetes => self.kubernetes += 1,
            StatsBucket::Emails => self.emails += 1,
            StatsBucket::Macs => self.macs += 1,
        }
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
            cpu_quantities: self.cpu_quantities,
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
            macs: self.macs,
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
    cpu_quantities: usize,
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
    macs: usize,
}

// -------------------------------------------------------------------------
// --preflight JSON schema is the Briefing (src/briefing.rs), serialized
// pretty to stdout. See `PatternFolder::build_briefing`.
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
    /// `--explain` only: the group this one came closest to joining. Absent
    /// otherwise, so default output is byte-identical with the flag off.
    #[serde(skip_serializing_if = "Option::is_none")]
    nearest: Option<Nearest>,
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
    briefing: crate::briefing::Briefing,
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
    /// How many groups could not be kept mergeable across an eviction
    /// (lessence-940) because `RETAINED_TEMPLATE_CAP` was already full when
    /// they evicted, and so were emitted immediately instead — the same
    /// fragmentation risk as before this feature, bounded rather than
    /// silently absent. Zero on every corpus this project measures against.
    fragmented_by_retention_cap: usize,
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
/// as the key in the `variation` map. Projection of the token taxonomy
/// (`Token::facts` in `patterns/mod.rs`).
fn token_type_name(token: &Token) -> &'static str {
    token.facts().machine_name
}

/// Extract the first `Token::Timestamp(s)` value from a slice, if any.
fn first_timestamp_in(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|t| match t {
        Token::Timestamp(s) => Some(s.clone()),
        _ => None,
    })
}

/// A group's first- and last-member epoch, for the briefing's per-template
/// count-over-span column. `first()`/`last()` are the group's earliest- and
/// most-recently-added members, which are in file order on the sequential
/// path (the only path `template_counts.record` is called from).
fn group_epoch_range(group: &PatternGroup) -> (Option<i64>, Option<i64>) {
    let first = first_timestamp_in(&group.first().tokens)
        .as_deref()
        .and_then(crate::briefing::epoch_seconds);
    let last = first_timestamp_in(&group.last().tokens)
        .as_deref()
        .and_then(crate::briefing::epoch_seconds);
    (first, last)
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
    /// VARIES only: how many members carried each sample, same order.
    pub counts: Option<Vec<usize>>,
}

#[derive(Serialize)]
struct JsonVariationEntry {
    distinct_count: usize,
    distinct_count_kind: &'static str,
    samples: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sample_counts: Option<Vec<usize>>,
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
            sample_counts: entry.counts,
            capped: entry.capped,
        }
    }
}

/// Full rollup for a single group — a sorted map from token type name to
/// its variation entry. BTreeMap gives deterministic iteration order,
/// which flows through to the JSON field order.
type GroupRollup = BTreeMap<&'static str, VariationEntry>;

/// Is this token type worth surfacing as samples (i.e., does the value
/// carry identity information useful to an agent)? Projection of the
/// token taxonomy; the identity-vs-measurement rationale is documented on
/// `KindFacts::sample_worthy` in `patterns/mod.rs`. The Phase 5
/// calibration may move token types between categories based on observed
/// real-world value-to-noise ratio.
fn is_sample_worthy(token: &Token) -> bool {
    token.facts().sample_worthy
}

/// Extract the string representation of a token for sampling.
/// Used only for sample-worthy token types; count-only types use
/// `hash_token_value` instead to avoid retaining large strings.
/// Projection of the token taxonomy (`Token::value_string`).
fn token_value_string(token: &Token) -> String {
    token.value_string()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Fold one byte slice into a running FNV-1a hash. Streaming this over a
/// token's constituent fields (with the same separators `value_string`
/// would insert between them) is byte-identical to hashing the
/// concatenated canonical string — FNV-1a's state carries across calls
/// regardless of how the bytes are chunked — without ever building that
/// `String`.
fn fnv1a_fold(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= u64::from(b);
        *h = h.wrapping_mul(FNV_PRIME);
    }
}

/// Fold a `u64`'s decimal digits into a running FNV-1a hash — the same
/// bytes `n.to_string().as_bytes()` would produce, without allocating.
fn fnv1a_fold_decimal(h: &mut u64, n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        let mut rest = n;
        while rest > 0 {
            i -= 1;
            buf[i] = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
    }
    fnv1a_fold(h, &buf[i..]);
}

/// Hash a token value to a u64. Used for count-only tracking of
/// high-cardinality types (Timestamp, Number, Duration, ...) where
/// retaining full strings would blow the memory budget, and now also for
/// every token's per-class cardinality estimator (lessence-nn3), which
/// runs once per token per line — allocation there is not affordable.
///
/// Streams FNV-1a directly over each variant's constituent `&str`/numeric
/// fields (with `value_string`'s exact separators) instead of building a
/// canonical `String` first, but is required to produce byte-identical
/// output to hashing that string — proven by
/// `hash_token_value_matches_value_string` for every variant.
///
/// Uses the same FNV-1a hashing as `seed_for_group` — NOT
/// `ahash::AHasher::default()` — so `distinct_count` is deterministic
/// across processes. For count-only types this mostly matters when the
/// distinct_cap is hit: the specific set of tracked hashes would
/// otherwise depend on per-process randomness, which in turn could
/// shift `distinct_count` by one on cap boundaries. Keeping everything
/// fixed-seed sidesteps that class of flake entirely.
fn hash_token_value(token: &Token) -> u64 {
    let mut h: u64 = FNV_OFFSET;
    match token {
        Token::Timestamp(s)
        | Token::IPv4(s)
        | Token::IPv6(s)
        | Token::Mac(s)
        | Token::Fqdn(s)
        | Token::Host(s)
        | Token::Uuid(s)
        | Token::Path(s)
        | Token::Json(s)
        | Token::Duration(s)
        | Token::CpuQuantity(s)
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
        | Token::Email(s) => fnv1a_fold(&mut h, s.as_bytes()),
        Token::Hash(_, s) => fnv1a_fold(&mut h, s.as_bytes()),
        Token::BracketContext(parts) => {
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    fnv1a_fold(&mut h, b",");
                }
                fnv1a_fold(&mut h, part.as_bytes());
            }
        }
        Token::Port(p) => fnv1a_fold_decimal(&mut h, u64::from(*p)),
        Token::HttpStatus(s) => fnv1a_fold_decimal(&mut h, u64::from(*s)),
        Token::Pid(p) => fnv1a_fold_decimal(&mut h, u64::from(*p)),
        Token::KeyValuePair { key, value_type } => {
            fnv1a_fold(&mut h, key.as_bytes());
            fnv1a_fold(&mut h, b"=");
            fnv1a_fold(&mut h, value_type.as_bytes());
        }
        Token::LogWithModule { level, module } => {
            fnv1a_fold(&mut h, level.as_bytes());
            fnv1a_fold(&mut h, b":");
            fnv1a_fold(&mut h, module.as_bytes());
        }
        Token::StructuredMessage { component, level } => {
            fnv1a_fold(&mut h, component.as_bytes());
            fnv1a_fold(&mut h, b":");
            fnv1a_fold(&mut h, level.as_bytes());
        }
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
/// Rollup key for words that differ between members of a group without any
/// detector having tokenised them. Sample-worthy: the values are the point.
pub(super) const VARIES: &str = "VARIES";
/// The placeholder a template shows where its members disagree.
pub(super) const VARIES_MARK: &str = "<VARIES>";

/// A line may join a group whose founder it disagrees with in at most this
/// many plain words.
const MAX_PLAIN_WORD_DIFFS: usize = 1;

/// Word alignment is exact up to this many words a side; past it a member
/// is aligned positionally when the counts agree and skipped otherwise.
const MAX_ALIGN_WORDS: usize = 256;

/// For each word of `a`, the index of the word of `b` it pairs with, by
/// longest common subsequence (positional when the counts agree, which is
/// the common case and needs no DP). `None` when the lines are too long to
/// align exactly and differ in word count.
pub(super) fn align_words(left: &[&str], right: &[&str]) -> Option<Vec<Option<usize>>> {
    if left.len() == right.len() {
        return Some((0..left.len()).map(Some).collect());
    }
    if left.len() > MAX_ALIGN_WORDS || right.len() > MAX_ALIGN_WORDS {
        return None;
    }
    // lcs[i][j] = LCS length of left[i..] and right[j..]
    let (rows, cols) = (left.len(), right.len());
    let mut lcs = vec![0u16; (rows + 1) * (cols + 1)];
    let idx = |i: usize, j: usize| i * (cols + 1) + j;
    for i in (0..rows).rev() {
        for j in (0..cols).rev() {
            lcs[idx(i, j)] = if left[i] == right[j] {
                lcs[idx(i + 1, j + 1)] + 1
            } else {
                lcs[idx(i + 1, j)].max(lcs[idx(i, j + 1)])
            };
        }
    }
    let mut out = vec![None; rows];
    let (mut i, mut j) = (0, 0);
    while i < rows && j < cols {
        if left[i] == right[j] {
            out[i] = Some(j);
            i += 1;
            j += 1;
        } else if lcs[idx(i + 1, j)] >= lcs[idx(i, j + 1)] {
            i += 1;
        } else {
            j += 1;
        }
    }
    Some(out)
}

/// Where a template unit and the member's aligned unit share a field name
/// or a bracket — `msg=Connecting` / `msg=Connected`, `"NodeName":"a"` /
/// `"NodeName":"b"`, `slot[1]` / `slot[2]` — the lengths of that shared
/// prefix (up to the last `=` `:` `[` `(`) and of the shared closing
/// brackets, so only the value between them varies.
fn shared_affixes(r: &str, w: &str) -> (usize, usize) {
    let (rb, wb) = (r.as_bytes(), w.as_bytes());
    let common = rb.iter().zip(wb).take_while(|(x, y)| x == y).count();
    let common = common.min(r.len() - 1).min(w.len() - 1);
    let prefix = rb[..common]
        .iter()
        .rposition(|&b| matches!(b, b'=' | b':' | b'[' | b'('))
        .map_or(0, |i| i + 1);
    let mut suffix = 0;
    while prefix + suffix + 1 < rb.len()
        && prefix + suffix + 1 < wb.len()
        && rb[rb.len() - 1 - suffix] == wb[wb.len() - 1 - suffix]
        && matches!(rb[rb.len() - 1 - suffix], b']' | b')')
    {
        suffix += 1;
    }
    (prefix, suffix)
}

/// The template spans a member turns into `<VARIES>`: every aligned pair
/// that differs (unless the template already varies there), minus a shared
/// field prefix, plus every template word the member has no counterpart for.
fn varying_spans(template: &str, member: &str) -> Vec<(usize, usize)> {
    let spans = unit_spans(template);
    let tmpl: Vec<&str> = spans
        .iter()
        .map(|&(at, len)| &template[at..at + len])
        .collect();
    let mem: Vec<&str> = unit_spans(member)
        .into_iter()
        .map(|(at, len)| &member[at..at + len])
        .collect();
    let Some(aligned) = align_words(&tmpl, &mem) else {
        return Vec::new();
    };
    let mut edits = Vec::new();
    let mut same_pci_identity = None;
    let mut same_option_identity = None;
    for (i, &(at, len)) in spans.iter().enumerate() {
        let r = tmpl[i];
        if r.contains(VARIES_MARK) || aligned[i].is_some_and(|j| mem[j] == r) {
            continue;
        }
        // An alignment shift around a shared PCI identity must not
        // erase it. Check the complete ordered list before preserving an
        // unmatched atom, so this helper is safe even outside an anchored
        // group. Most atoms align directly and never need this scan.
        if crate::normalize::pci_addresses(r)
            .next()
            .is_some_and(|m| m.start() == 0 && m.end() == r.len())
            && *same_pci_identity.get_or_insert_with(|| {
                crate::normalize::pci_addresses(template)
                    .map(|m| m.as_str())
                    .eq(crate::normalize::pci_addresses(member).map(|m| m.as_str()))
            })
        {
            continue;
        }
        if crate::normalize::cli_option_names(r)
            .next()
            .is_some_and(|m| m.start() == 0 && m.end() == r.len())
            && *same_option_identity.get_or_insert_with(|| {
                crate::normalize::cli_option_names(template)
                    .map(|m| m.as_str())
                    .eq(crate::normalize::cli_option_names(member).map(|m| m.as_str()))
            })
        {
            continue;
        }
        match aligned[i] {
            Some(j) => {
                let (p, q) = shared_affixes(r, mem[j]);
                edits.push((at + p, len - p - q));
            }
            None => edits.push((at, len)),
        }
    }
    edits
}

/// The letters of a word, in order: what the sentence says once digits
/// and punctuation — the values — are set aside. `slot[2]` and `slot[1]`
/// read the same; `create` and `delete` do not.
fn letters(w: &str) -> impl Iterator<Item = u8> + '_ {
    w.bytes().filter(u8::is_ascii_alphabetic)
}

/// The value of a `key=value` / `key:value` / `"key":value` word when its
/// key is a plain identifier; `None` for a structured key such as
/// `k8s:app` or `1:S`, whose whole word is data.
fn field_value(w: &str) -> Option<&str> {
    let plain = |k: &str| {
        k.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    if let Some(rest) = w.strip_prefix('"')
        && let Some(i) = rest.find("\":")
    {
        return plain(&rest[..i]).then(|| &rest[i + 2..]);
    }
    match w.find(['=', ':']) {
        Some(i) => plain(&w[..i]).then(|| &w[i + 1..]),
        None => Some(w),
    }
}

/// A word that is data, not sentence: a whole quoted value (`"icip"`), a
/// placeholder, a dotted or slashed name, a URL, a structured key. Two data
/// words may differ freely — a line may vary in as many values as it
/// likes. Everything else is a word of the sentence.
fn data_shaped(w: &str) -> bool {
    let w = w
        .trim_start_matches(['+', '-'])
        .trim_end_matches(['.', ',', ';', ':', '!', '?']);
    let Some(v) = field_value(w) else {
        return true;
    };
    // a bracketed value — `volumes=[valkey-data]`, `(6/0)` — is a value
    let bracketed =
        (v.starts_with('[') && v.ends_with(']')) || (v.starts_with('(') && v.ends_with(')'));
    bracketed
        || (v.len() >= 2 && v.starts_with('"') && v.ends_with('"'))
        || v.bytes()
            .any(|b| matches!(b, b'/' | b'.' | b'*' | b'<' | b'>' | b'\\' | b'@' | b'='))
}

/// The units of a line: its words, except that a quoted string with spaces
/// in it — `controller="crt configmap"`, `err="context deadline exceeded"`
/// — is one unit, because a value with spaces is still one value. Byte
/// spans into `s`, each covering the words of the unit and the spaces
/// between them.
fn word_unit_spans(s: &str) -> Vec<(usize, usize)> {
    /// A quoted string of more words than this is a sentence — the event's
    /// own words, each its own unit — not a value with spaces in it.
    const VALUE_WORDS: usize = 3;
    let mut units: Vec<(usize, usize)> = Vec::with_capacity(16);
    let mut open: Vec<(usize, usize)> = Vec::new();
    let close = |units: &mut Vec<(usize, usize)>, open: &mut Vec<(usize, usize)>| {
        if open.len() <= VALUE_WORDS {
            let (start, _) = open[0];
            let (at, len) = open[open.len() - 1];
            units.push((start, at + len - start));
        } else {
            units.extend(open.iter().copied());
        }
        open.clear();
    };
    for (at, len) in word_spans(s) {
        let quotes = s[at..at + len].bytes().filter(|&b| b == b'"').count();
        if open.is_empty() {
            if quotes % 2 == 1 {
                open.push((at, len));
            } else {
                units.push((at, len));
            }
        } else {
            open.push((at, len));
            if quotes % 2 == 1 {
                close(&mut units, &mut open);
            }
        }
    }
    if !open.is_empty() {
        close(&mut units, &mut open);
    }
    units
}

/// Split option names and their enclosing quote delimiters into stable atoms.
/// A short quoted command is otherwise one value: changing its argument
/// would erase the option too. Keeping the quotes also keeps later JSON
/// fields outside that value when the argument becomes <VARIES>.
fn cli_option_units(s: &str, units: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let options: Vec<_> = crate::normalize::cli_option_names(s).collect();
    if options.is_empty() {
        return units;
    }
    let mut ranges: Vec<_> = options.iter().map(regex::Match::range).collect();
    let mut boundaries: Vec<_> = options.iter().flat_map(|m| [m.start(), m.end()]).collect();
    let (mut opening, mut escaped, mut option_index) = (None, false, 0);
    for (at, byte) in s.bytes().enumerate() {
        if byte == b'"' && !escaped {
            if let Some(start) = opening.take() {
                while option_index < options.len() && options[option_index].start() < start {
                    option_index += 1;
                }
                if option_index < options.len() && options[option_index].end() <= at {
                    ranges.push(start..at + 1);
                    boundaries.extend([start, start + 1, at, at + 1]);
                }
            } else {
                opening = Some(at);
            }
        }
        escaped = byte == b'\\' && !escaped;
    }
    ranges.sort_unstable_by_key(|range| range.start);
    boundaries.sort_unstable();
    boundaries.dedup();
    let mut split = Vec::with_capacity(units.len() + boundaries.len());
    let (mut range_index, mut boundary_index) = (0, 0);
    for (at, len) in units {
        while range_index < ranges.len() && ranges[range_index].end <= at {
            range_index += 1;
        }
        if range_index == ranges.len() || ranges[range_index].start >= at + len {
            split.push((at, len));
            continue;
        }
        for (word_at, word_len) in word_spans(&s[at..at + len]) {
            let start = at + word_at;
            let end = start + word_len;
            let mut cursor = start;
            while boundary_index < boundaries.len() && boundaries[boundary_index] <= start {
                boundary_index += 1;
            }
            while boundary_index < boundaries.len() && boundaries[boundary_index] < end {
                let boundary = boundaries[boundary_index];
                split.push((cursor, boundary - cursor));
                cursor = boundary;
                boundary_index += 1;
            }
            split.push((cursor, end - cursor));
        }
    }
    split
}

/// Template units keep quoted CLI/HTTP fields separate and each PCI
/// identity atomic, even inside a path.
/// Splitting byte spans inserts no whitespace into the shown template.
/// The join policy still uses the original word units below.
pub(super) fn unit_spans(s: &str) -> Vec<(usize, usize)> {
    let mut units = word_unit_spans(s);
    if s.contains("HTTP/") {
        let requests: Vec<_> = crate::normalize::quoted_request_templates(s).collect();
        if !requests.is_empty() {
            let mut boundaries: Vec<_> = requests
                .iter()
                .flat_map(|(request, protocol)| {
                    let quote = usize::from(request.as_str().ends_with('"'));
                    [request.start() + 1, protocol.end(), request.end() - quote]
                })
                .collect();
            // An empty version puts the version boundary and closing
            // quote at the same byte. Matches and their cuts are ordered.
            boundaries.dedup();
            let mut split = Vec::with_capacity(units.len() + requests.len() * 5);
            let (mut request_index, mut boundary_index) = (0, 0);
            for (at, len) in units {
                while request_index < requests.len() && requests[request_index].0.end() <= at {
                    request_index += 1;
                }
                if request_index == requests.len() || requests[request_index].0.start() >= at + len
                {
                    split.push((at, len));
                    continue;
                }
                for (word_at, word_len) in word_spans(&s[at..at + len]) {
                    let start = at + word_at;
                    let end = start + word_len;
                    let mut cursor = start;
                    while boundary_index < boundaries.len() && boundaries[boundary_index] <= start {
                        boundary_index += 1;
                    }
                    while boundary_index < boundaries.len() && boundaries[boundary_index] < end {
                        let boundary = boundaries[boundary_index];
                        split.push((cursor, boundary - cursor));
                        cursor = boundary;
                        boundary_index += 1;
                    }
                    split.push((cursor, end - cursor));
                }
            }
            units = split;
        }
    }
    units = cli_option_units(s, units);
    let mut pci = crate::normalize::pci_addresses(s).peekable();
    if pci.peek().is_none() {
        return units;
    }
    let mut split = Vec::with_capacity(units.len() + 4);
    for (at, len) in units {
        let end = at + len;
        let mut cursor = at;
        while let Some(address) = pci.peek() {
            if address.start() >= end {
                break;
            }
            // PCI syntax contains no word/quote separators, so every
            // address fits wholly within one original unit.
            debug_assert!(address.start() >= cursor && address.end() <= end);
            if cursor < address.start() {
                split.push((cursor, address.start() - cursor));
            }
            split.push((address.start(), address.len()));
            cursor = address.end();
            pci.next();
        }
        if cursor < end {
            split.push((cursor, end - cursor));
        }
    }
    split
}

/// How many words two lines disagree in where the disagreement is one of
/// sentence, not of value: the letters differ and at least one side is not
/// data. `Fork CoW for RDB` against `Fork CoW for AOF rewrite` is three,
/// `user alice` against `user bob` is one, and `Failed to watch *v1.Node:
/// nodes … "nodes"` against the same for pods is one (`nodes`; the typed
/// and quoted forms are values). A quoted value with spaces is one unit:
/// `"crt configmap"` against `"token_cleaner"` is one, while a quoted
/// sentence still counts each word that changed.
pub(super) fn plain_word_diffs(a: &str, b: &str) -> usize {
    let differs =
        |x: &str, y: &str| !(letters(x).eq(letters(y)) || (data_shaped(x) && data_shaped(y)));
    let lone = |x: &str| letters(x).next().is_some() && !data_shaped(x);
    let ua: Vec<&str> = word_unit_spans(a)
        .into_iter()
        .map(|(at, len)| &a[at..at + len])
        .collect();
    let ub: Vec<&str> = word_unit_spans(b)
        .into_iter()
        .map(|(at, len)| &b[at..at + len])
        .collect();
    let Some(aligned) = align_words(&ua, &ub) else {
        return 0;
    };
    // Two units that differ: word by word, for single words and quoted
    // sentences alike; a unit shorter than its counterpart is at most one
    // further disagreement — a value that gained a word is still one value.
    let unit_diffs = |x: &str, y: &str| -> usize {
        let xs: Vec<&str> = x.split_whitespace().collect();
        let ys: Vec<&str> = y.split_whitespace().collect();
        let n = xs.len().min(ys.len());
        let mut d = xs
            .iter()
            .zip(&ys)
            .filter(|(p, q)| p != q && differs(p, q))
            .count();
        if xs.len() != ys.len() {
            d += usize::from(xs[n..].iter().chain(&ys[n..]).any(|w| lone(w)));
        }
        d
    };
    // A word one line has and the other lacks is a new sentence word only
    // if the other line has it nowhere: a list that grew by one entry
    // (`partial failures: [a: … cache], [b: … cache]`) repeats words the
    // shorter line already carries.
    let lone_unit = |u: &str, other: &[&str]| {
        u.split_whitespace()
            .any(|w| lone(w) && !other.iter().any(|o| o.split_whitespace().any(|x| x == w)))
    };
    let mut matched_b = vec![false; ub.len()];
    let mut diffs = 0;
    for (i, &x) in ua.iter().enumerate() {
        match aligned[i] {
            Some(j) => {
                matched_b[j] = true;
                if x != ub[j] {
                    diffs += unit_diffs(x, ub[j]);
                }
            }
            None if lone_unit(x, &ub) => diffs += 1,
            None => {}
        }
    }
    diffs
        + ub.iter()
            .zip(&matched_b)
            .filter(|(u, m)| !**m && lone_unit(u, &ua))
            .count()
}

fn seed_for_group(normalized: &str) -> u64 {
    let mut h = FNV_OFFSET;
    fnv1a_fold(&mut h, normalized.as_bytes());
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
            // Inline samples when the full distinct set fits. Words no
            // detector claimed are shown with their counts whatever the
            // set size: the distribution is the point.
            if let Some(counts) = &entry.counts {
                out.push_str(" {");
                let shown: Vec<String> = entry
                    .samples
                    .iter()
                    .zip(counts)
                    .map(|(s, n)| format!("{}×{n}", truncate_sample(s)))
                    .collect();
                out.push_str(&shown.join(", "));
                if entry.distinct_count > entry.samples.len() {
                    out.push_str(", …");
                }
                out.push('}');
            } else if entry.distinct_count <= inline_threshold
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
#[derive(Debug)]
enum Accumulator {
    /// Sample-worthy: retain full values so we can draw samples.
    Values(HashSet<String>),
    /// Count-only: retain only hashes so memory stays bounded.
    Hashes(HashSet<u64>),
    /// Words no detector claimed, with how many members carried each: the
    /// samples are the most frequent plus the rarest, never a random draw.
    Counted(HashMap<String, usize>),
}

impl Accumulator {
    fn len(&self) -> usize {
        match self {
            Self::Values(s) => s.len(),
            Self::Hashes(s) => s.len(),
            Self::Counted(m) => m.len(),
        }
    }

    /// An empty accumulator of the same kind.
    fn empty_like(other: &Self) -> Self {
        match other {
            Self::Values(_) => Self::Values(HashSet::new()),
            Self::Hashes(_) => Self::Hashes(HashSet::new()),
            Self::Counted(_) => Self::Counted(HashMap::new()),
        }
    }
}

/// Stateless rollup computer. One per `PatternFolder`. Parameters
/// (K, distinct_cap) are supplied by the constructor, defaulting to
/// the calibrated `ROLLUP_*` constants via `with_defaults`.
struct RollupComputer {
    k: usize,
    distinct_cap: usize,
    /// `--sanitize`: a VARIES value is counted in its masked form, so
    /// `password=FIXVALUEA1` lands in the rollup as `<SECRET>` — the slot
    /// has already dropped the `password=` that the credential mask keys on.
    sanitizer: Option<Sanitizer>,
}

impl RollupComputer {
    fn new(k: usize, distinct_cap: usize) -> Self {
        Self {
            k,
            distinct_cap,
            sanitizer: None,
        }
    }

    fn with_defaults() -> Self {
        Self::new(ROLLUP_K, ROLLUP_DISTINCT_CAP)
    }

    fn sanitized(mut self, sanitizer: Option<Sanitizer>) -> Self {
        self.sanitizer = sanitizer;
        self
    }

    /// Bucket every token of `lines` into `per_type`'s accumulators —
    /// the token-type half of a group's rollup. Shared by a full-group
    /// scan (`compute`, `seed`) and a single-member extension of an
    /// already-seeded accumulator (`PatternGroup::retained_rejoin`), so a
    /// group that has been evicted from the live buffer keeps accumulating
    /// this state one member at a time instead of needing every member
    /// re-scanned (lessence-940).
    fn accumulate_tokens(
        &self,
        lines: &[LogLine],
        per_type: &mut BTreeMap<&'static str, (Accumulator, bool)>,
    ) {
        // Upper bound on distinct values per token type: can't exceed the
        // number of lines passed in. Pre-allocating HashSets with this hint
        // avoids the grow-rehash cycle that shows up disproportionately in
        // parallel-mode flush timing. For a single-member call (a rejoin)
        // this is just 1 — the hint only matters for a fresh accumulator.
        let capacity_hint = lines.len().min(self.distinct_cap);

        for line in lines {
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
                    // words are counted in their own pass below
                    Accumulator::Counted(_) => {}
                }
            }
        }
    }

    /// Words the detectors never touched can still differ between
    /// members — `Configuring patroni` folded with `Configuring crontab`
    /// because eight words in nine match. Tokens are the only thing
    /// `accumulate_tokens` can see, so without this pass the rollup would
    /// report those ten subsystems as one, and "zero data loss" would hold
    /// only for tokenised variation (lessence-w1p). Compare each member to
    /// `template`'s words; a differing word that is not a placeholder is
    /// reported under VARIES like any other type. Every word is counted,
    /// the representative's included, because an agent reading `Server
    /// Busy` needs to know that one member in 7,165 said `Server Reject` —
    /// the count is what makes rare visible. The template is authoritative:
    /// every `<VARIES>` it carries is a slot, and each member's word
    /// aligned to that slot is counted — minus the `key=` prefix the slot
    /// kept. A member that has no word there (a shorter line) counts as
    /// `∅`, so an absence is visible.
    ///
    /// Shared the same way `accumulate_tokens` is: a full-group scan seeds
    /// `varies`; retained positional members extend it one line at a time.
    /// Retained unequal-length forms are aligned against the final template.
    fn accumulate_varies(
        &self,
        lines: &[LogLine],
        template: &str,
        varies: &mut HashMap<String, usize>,
        varies_capped: &mut bool,
    ) {
        self.accumulate_varies_counted(
            lines.iter().map(|line| (line.normalized.as_str(), 1)),
            template,
            varies,
            varies_capped,
        );
    }

    fn accumulate_varies_counted<'a>(
        &self,
        lines: impl Iterator<Item = (&'a str, usize)>,
        template: &str,
        varies: &mut HashMap<String, usize>,
        varies_capped: &mut bool,
    ) {
        let tmpl_words: Vec<&str> = unit_spans(template)
            .into_iter()
            .map(|(at, len)| &template[at..at + len])
            .collect();
        let slots: Vec<(usize, usize, usize)> = tmpl_words
            .iter()
            .enumerate()
            .filter_map(|(i, w)| {
                w.find(VARIES_MARK)
                    .map(|k| (i, k, w.len() - k - VARIES_MARK.len()))
            })
            .collect();
        if slots.is_empty() {
            return;
        }
        for (normalized, count) in lines {
            let member: Vec<&str> = unit_spans(normalized)
                .into_iter()
                .map(|(at, len)| &normalized[at..at + len])
                .collect();
            let Some(aligned) = align_words(&tmpl_words, &member) else {
                continue;
            };
            for &(i, k, q) in &slots {
                let masked;
                let value = match aligned[i] {
                    Some(j) => {
                        let w = if let Some(z) = &self.sanitizer {
                            masked = z.mask_text(member[j]);
                            masked.as_str()
                        } else {
                            member[j]
                        };
                        let prefix = &tmpl_words[i][..k];
                        let suffix = &tmpl_words[i][tmpl_words[i].len() - q..];
                        w.strip_prefix(prefix)
                            .and_then(|v| v.strip_suffix(suffix))
                            .unwrap_or(w)
                    }
                    None => "∅",
                };
                if let Some(n) = varies.get_mut(value) {
                    *n += count;
                } else if varies.len() < self.distinct_cap {
                    varies.insert(value.to_string(), count);
                } else {
                    *varies_capped = true;
                }
            }
        }
    }

    fn accumulate_retained_varies(
        &self,
        line: &LogLine,
        template: &str,
        state: &mut RetainedState,
    ) {
        if unit_spans(&line.normalized).len() == unit_spans(template).len() {
            state.positional_members += 1;
            self.accumulate_varies(
                std::slice::from_ref(line),
                template,
                &mut state.varies,
                &mut state.varies_capped,
            );
        } else {
            self.retain_realign_form(state, &line.normalized, 1);
        }
    }

    fn retain_realign_form(&self, state: &mut RetainedState, form: &str, count: usize) {
        if let Some(n) = state.realign.get_mut(form) {
            *n += count;
        } else if state.realign.len() < self.distinct_cap {
            state.realign.insert(form.to_string(), count);
        } else {
            state.realign_capped = true;
        }
    }

    /// A newly varying slot was a literal shared by all positional members.
    /// Account for those discarded members without inventing a sample or
    /// retaining their raw lines. Existing varying slots are never edited
    /// by `varying_spans`, so their accumulated counts remain untouched.
    fn accumulate_new_varies(
        &self,
        template: &str,
        edits: &[(usize, usize)],
        state: &mut RetainedState,
    ) {
        if edits.is_empty() {
            return;
        }
        let units = unit_spans(template);
        for &(at, len) in edits {
            let &(start, width) = units
                .iter()
                .find(|&&(start, width)| start <= at && at + len <= start + width)
                .expect("a varying edit is inside one template unit");
            let unit = &template[start..start + width];
            let masked;
            let value = if let Some(z) = &self.sanitizer {
                masked = z.mask_text(unit);
                masked.as_str()
            } else {
                unit
            };
            let value = value
                .strip_prefix(&template[start..at])
                .and_then(|v| v.strip_suffix(&template[at + len..start + width]))
                .unwrap_or(value);
            if let Some(n) = state.varies.get_mut(value) {
                *n += state.positional_members;
            } else if state.varies.len() < self.distinct_cap {
                state
                    .varies
                    .insert(value.to_string(), state.positional_members);
            } else {
                state.varies_capped = true;
            }
        }
    }

    /// Compute the rollup for a group that has never been evicted from the
    /// live buffer: seeds fresh accumulators from its full member list and
    /// finalises immediately. Complexity: O(total_tokens_in_group). Memory
    /// bound: `sum(min(distinct, cap)) × per-entry-size`, where
    /// per-entry-size is `sizeof(u64)` for count-only and `value_len` for
    /// sample-worthy.
    fn compute(&self, group: &PatternGroup) -> GroupRollup {
        let mut per_type: BTreeMap<&'static str, (Accumulator, bool)> = BTreeMap::new();
        self.accumulate_tokens(&group.lines, &mut per_type);
        let mut varies: HashMap<String, usize> = HashMap::new();
        let mut varies_capped = false;
        self.accumulate_varies(
            &group.lines,
            group.template(),
            &mut varies,
            &mut varies_capped,
        );
        self.finalize(
            per_type,
            varies,
            varies_capped,
            group.template(),
            &group.first().normalized,
        )
    }

    /// Seed a retained group's accumulator at the moment it is evicted from
    /// the live buffer: one full scan of its current member list — the
    /// last point that full list exists — after which `PatternGroup::lines`
    /// is truncated and further members extend this state one at a time.
    fn seed(&self, group: &PatternGroup) -> RetainedState {
        let mut state = RetainedState::default();
        self.accumulate_tokens(&group.lines, &mut state.per_type);
        for line in &group.lines {
            self.accumulate_retained_varies(line, group.template(), &mut state);
        }
        state
    }

    /// Finalise a retained group's accumulator into a `GroupRollup`, at
    /// actual emission — the one point a retained group is rendered.
    /// `template` is the group's final template;
    /// `seed_key` reproduces the same per-group sample-draw seed `compute`
    /// uses (the founding line's normalized text).
    fn finalize_retained(
        &self,
        mut state: RetainedState,
        template: &str,
        seed_key: &str,
    ) -> GroupRollup {
        if state.realign_capped {
            // Unknown alignments can affect any VARIES value's count. Do
            // not label partial counts as exact: expose an empty, capped
            // variation entry. Token rollups and the group count survive.
            state.varies.clear();
            state.varies_capped = true;
        } else {
            self.accumulate_varies_counted(
                state.realign.iter().map(|(text, &n)| (text.as_str(), n)),
                template,
                &mut state.varies,
                &mut state.varies_capped,
            );
        }
        self.finalize(
            state.per_type,
            state.varies,
            state.varies_capped,
            template,
            seed_key,
        )
    }

    /// Merge one retained accumulator into another (lessence-682): the
    /// union of each token type's distinct set and the sum of each varying
    /// word's count, under the same `distinct_cap` a single group obeys.
    fn merge_retained(&self, into: &mut RetainedState, from: RetainedState) {
        into.positional_members += from.positional_members;
        into.realign_capped |= from.realign_capped;
        for (form, n) in from.realign {
            self.retain_realign_form(into, &form, n);
        }
        for (name, (acc, capped)) in from.per_type {
            let entry = into
                .per_type
                .entry(name)
                .or_insert_with(|| (Accumulator::empty_like(&acc), false));
            if capped {
                entry.1 = true;
            }
            match (&mut entry.0, acc) {
                (Accumulator::Values(s), Accumulator::Values(other)) => {
                    // Capped means some values are unknown, not that the
                    // known ones may be discarded. Sort before filling any
                    // remaining room so samples do not depend on hash order.
                    let mut other: Vec<_> = other.into_iter().collect();
                    other.sort_unstable();
                    for v in other {
                        if s.contains(&v) {
                            continue;
                        }
                        if s.len() >= self.distinct_cap {
                            entry.1 = true;
                            break;
                        }
                        s.insert(v);
                    }
                }
                (Accumulator::Hashes(s), Accumulator::Hashes(other)) => {
                    let mut other: Vec<_> = other.into_iter().collect();
                    other.sort_unstable();
                    for v in other {
                        if s.contains(&v) {
                            continue;
                        }
                        if s.len() >= self.distinct_cap {
                            entry.1 = true;
                            break;
                        }
                        s.insert(v);
                    }
                }
                (Accumulator::Counted(m), Accumulator::Counted(other)) => {
                    for (k, n) in other {
                        *m.entry(k).or_insert(0) += n;
                    }
                }
                // The two groups share a template, so a token type is
                // sample-worthy in both or in neither; a mismatch cannot
                // happen, and if it did the entry is left as it was.
                _ => {}
            }
        }
        for (value, n) in from.varies {
            if let Some(m) = into.varies.get_mut(&value) {
                *m += n;
            } else if into.varies.len() < self.distinct_cap {
                into.varies.insert(value, n);
            } else {
                into.varies_capped = true;
            }
        }
        into.varies_capped |= from.varies_capped;
    }

    /// Draw samples deterministically from each Accumulator and produce one
    /// `VariationEntry` per token type that appeared. Seed is per-group so
    /// the same template → the same draw, regardless of how the
    /// accumulators were built (one scan, or a scan plus incremental
    /// extensions).
    fn finalize(
        &self,
        mut per_type: BTreeMap<&'static str, (Accumulator, bool)>,
        varies: HashMap<String, usize>,
        varies_capped: bool,
        template: &str,
        seed_key: &str,
    ) -> GroupRollup {
        if template.contains(VARIES_MARK) {
            per_type.insert(VARIES, (Accumulator::Counted(varies), varies_capped));
        }
        let mut rng = ChaCha8Rng::seed_from_u64(seed_for_group(seed_key));
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
                Accumulator::Counted(m) => {
                    let mut by_count: Vec<(String, usize)> = m.into_iter().collect();
                    by_count.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    let mut picked: Vec<(String, usize)> = if by_count.len() > self.k {
                        // the top k-1, and the rarest: rare is signal
                        let rarest = by_count.pop().unwrap();
                        by_count.truncate(self.k - 1);
                        by_count.push(rarest);
                        by_count
                    } else {
                        by_count
                    };
                    let counts: Vec<usize> = picked.iter().map(|(_, n)| *n).collect();
                    let samples: Vec<String> = picked.drain(..).map(|(w, _)| w).collect();
                    out.insert(
                        name,
                        VariationEntry {
                            distinct_count,
                            samples,
                            capped,
                            counts: Some(counts),
                        },
                    );
                    continue;
                }
            };
            out.insert(
                name,
                VariationEntry {
                    distinct_count,
                    samples,
                    capped,
                    counts: None,
                },
            );
        }
        out
    }
}

impl PatternFolder {
    pub fn new(config: Config) -> Self {
        let sanitizer = config.sanitizer();
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
            rollup_computer: RollupComputer::with_defaults().sanitized(sanitizer.clone()),
            sanitizer,
            distill_kept: Vec::new(),
            distill_templates: Vec::new(),
            distill_rates: crate::distill::rates::Rates::new(),
            retained: ahash::AHashMap::new(),
            retained_index: retained_index::RetainedIndex::default(),
            json_retention_cap_hits: 0,
        }
    }

    /// --distill: the input line numbers the distillation keeps and the
    /// template of every group that formed. Call after `finish()`.
    pub fn take_distilled(&mut self) -> (Vec<usize>, Vec<String>) {
        (
            std::mem::take(&mut self.distill_kept),
            std::mem::take(&mut self.distill_templates),
        )
    }

    pub(crate) fn take_distilled_rates(&mut self) -> crate::distill::rates::Rates {
        std::mem::take(&mut self.distill_rates)
    }

    /// Absorb the ingestion outcome for the completeness section of the
    /// JSONL summary record. One call after `Ingestor::run`, replacing the
    /// order-sensitive per-fact callbacks main used to invoke; the group
    /// and variation completeness fields are derived internally by the
    /// fold/finish paths. The fields set here are only read when the JSON
    /// summary record is rendered.
    pub fn absorb_ingest_report(&mut self, report: &IngestReport, any_source_failed: bool) {
        self.json_skipped_overlong_lines += report.overlong_lines_skipped;
        // `--frame-continuations` delivers a stack trace as one record, so the
        // per-record tally under-reports the file. Add the merged lines back:
        // they were read and they are represented in the output, just not as
        // records of their own. Without this the input size and the
        // compression ratio both understate what was processed.
        self.stats.total_lines += report.continuation_lines_absorbed;
        // They are also lines the reader never has to look at, so they count
        // as saved too — otherwise the ratio would report framing as pure
        // input growth with no benefit.
        self.stats.lines_saved += report.continuation_lines_absorbed;
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
        // Format/level classification reads mostly off the tokens just
        // computed, falling back to a bounded byte scan only when nothing
        // free answered the level — see `record_briefing_line`.
        self.stats
            .record_briefing_line(&normalized_line.tokens, line);
        self.stats.record_span(&normalized_line.tokens);

        // Try to find a matching group in the buffer
        self.cluster_line_at(normalized_line, location);

        // Smart flushing: flush groups that are old enough to be safe
        if self.should_flush_buffer() {
            return self.flush_oldest_safe_group();
        }

        Ok(None)
    }

    /// The buffered group `line` scored highest against, with the first token
    /// that differs. Full `similarity_score` on every group, so this is only
    /// ever called under `--explain`.
    fn nearest_group(&self, line: &LogLine) -> Option<Nearest> {
        let (idx, score) = self
            .buffer
            .iter()
            .enumerate()
            .map(|(i, g)| (i, self.normalizer.similarity_score(line, g.first())))
            .max_by(|a, b| a.1.total_cmp(&b.1))?;
        let nearest = &self.buffer[idx];
        Some(Nearest {
            group_line_no: nearest.first_line_no,
            score: (score * 10.0).round() / 10.0,
            anchor_mismatch: line.anchor != nearest.first().anchor,
            first_diff: first_diff(line, nearest.first()),
        })
    }

    /// Attach a normalized line to its group: O(1) exact-hash lookup via
    /// `group_index` first, then the linear similarity scan, then a new
    /// group. The hash shortcut picks the same group the scan would (see
    /// the `group_index` field docs).
    fn cluster_line_at(&mut self, normalized_line: LogLine, location: Option<LineLocation>) {
        // A line whose hash matches a group that has already been evicted
        // from the live buffer rejoins it directly (lessence-940) instead
        // of founding a fresh group under the same template. `group_index`
        // and `retained` share one key space and are never both populated
        // for the same hash, so this check and the one below it are
        // mutually exclusive.
        if let Some(group) = self.retained.get_mut(&normalized_line.hash) {
            let loc = location
                .unwrap_or_else(|| LineLocation::new(SourceId::STDIN, self.position_counter));
            group.retained_rejoin(normalized_line, loc, &self.rollup_computer);
            return;
        }
        let match_index = if let Some(&idx) = self.group_index.get(&normalized_line.hash) {
            Some(idx)
        } else {
            // Similar is not the same: a line that agrees with a group's
            // founder in shape but disagrees in two plain words — the verb
            // and the outcome, the subsystem and the state — is another
            // event that happens to read alike (`Synchronization … succeeded`
            // beside `Connection … lost.`). One differing word is a name or
            // a value and folds; two are a different sentence.
            let retained_match = if self.retained.is_empty() {
                None
            } else {
                self.retained_index
                    .candidates(&normalized_line, self.config.threshold)
                    .into_iter()
                    .filter_map(|key| {
                        let group = self.retained.get(&key)?;
                        (self.normalizer.are_similar(&normalized_line, group.first())
                            && plain_word_diffs(
                                &normalized_line.normalized,
                                &group.first().normalized,
                            ) <= MAX_PLAIN_WORD_DIFFS)
                            .then_some((group.position, key))
                    })
                    .min_by_key(|&(position, _)| position)
            };
            let before = retained_match.map_or(usize::MAX, |(position, _)| position);
            // The live buffer remains in founder order after removals.
            // A matching retained founder rules out every newer live one.
            let live_match = self
                .buffer
                .iter()
                .take_while(|g| g.position < before)
                .position(|group| {
                    let first = group.first();
                    self.normalizer.are_similar(&normalized_line, first)
                        && plain_word_diffs(&normalized_line.normalized, &first.normalized)
                            <= MAX_PLAIN_WORD_DIFFS
                });
            if live_match.is_none()
                && let Some((_, key)) = retained_match
            {
                let loc = location
                    .unwrap_or_else(|| LineLocation::new(SourceId::STDIN, self.position_counter));
                self.retained
                    .get_mut(&key)
                    .expect("indexed retained group")
                    .retained_rejoin(normalized_line, loc, &self.rollup_computer);
                return;
            }
            live_match
        };

        // --distill needs every member's input line number, since the
        // member that carries a rare variant can sit anywhere in a group.
        let distill_line_no = self
            .config
            .distill
            .is_some()
            .then(|| location.map_or(self.position_counter, |l| l.line_no));

        if let Some(index) = match_index {
            if let Some(location) = location {
                self.buffer[index].add_line_at(normalized_line, location);
            } else {
                self.buffer[index].add_line(normalized_line, self.position_counter);
            }
            if let Some(line_no) = distill_line_no {
                self.buffer[index].member_line_nos.push(line_no);
            }
        } else {
            // --explain: the line is about to found a group. Before it does,
            // record which existing group it came closest to joining and
            // where the two first disagree. Diagnostics only — the decision
            // above is already made and this cannot change it.
            let nearest = self
                .config
                .explain
                .then(|| self.nearest_group(&normalized_line))
                .flatten();

            // Create a new group at current position
            let rep_hash = normalized_line.hash;
            let mut group = if let Some(location) = location {
                PatternGroup::new_at(normalized_line, self.position_counter, location)
            } else {
                PatternGroup::new(normalized_line, self.position_counter)
            };
            group.nearest = nearest;
            if let Some(line_no) = distill_line_no {
                group.member_line_nos.push(line_no);
            }
            self.buffer.push(group);
            let prev = self.group_index.insert(rep_hash, self.buffer.len() - 1);
            debug_assert!(prev.is_none(), "duplicate representative hash in buffer");
        }
    }

    /// --distill: record what a distillation of this group must carry —
    /// its template, and the input line numbers of the members to keep.
    ///
    /// "The first N members" is not enough. When a group over-folded two
    /// events into one, the rarer event may sit at member 7,000, and a
    /// distillation that dropped it could never show the defect. What makes
    /// a member worth keeping is its normalized form: the template is built
    /// by folding every distinct normalized form of the group into
    /// `<VARIES>`, and the rollup lists exactly those forms' differences. So
    /// the first member of every distinct normalized form is kept — bounded
    /// by the same [`ROLLUP_DISTINCT_CAP`] the rollup reports to — and only
    /// then are the earliest remaining members added until `members` is
    /// reached, plus a log-scaled sample spread evenly over the occurrences
    /// (`3 + floor(log2 n)`, capped at 16), so a distillation of a huge group
    /// is a miniature spanning its whole run rather than just its head. A
    /// group too small to collapse keeps every line: those are not folded
    /// away, they are the log.
    fn distill_take(&mut self, group: &PatternGroup, members: usize) {
        self.distill_templates.push(group.template().to_string());
        let rates = self
            .distill_rates
            .entry(group.template().to_string())
            .or_default();
        for (line, &line_no) in group.lines.iter().zip(&group.member_line_nos) {
            rates.record(line_no, &line.tokens);
        }
        if !group.should_collapse(self.config.min_collapse) {
            self.distill_kept
                .extend(group.member_line_nos.iter().copied());
            return;
        }

        let mut chosen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();

        // The members that built the template, replayed exactly as
        // `add_line_at` built it: a member that turned some template word
        // into `<VARIES>` is the only evidence that word varies, and without
        // it the distilled file would claim a literal the original never
        // claimed. There is no cap here — the set cannot be larger than the
        // template has words.
        let mut template = group.lines[0].normalized.clone();
        chosen.insert(0);
        for (idx, line) in group.lines.iter().enumerate().skip(1) {
            if line.hash == group.lines[0].hash {
                continue;
            }
            let edits = varying_spans(&template, &line.normalized);
            if edits.is_empty() {
                continue;
            }
            for (at, len) in edits.into_iter().rev() {
                template.replace_range(at..at + len, VARIES_MARK);
            }
            chosen.insert(idx);
        }

        // Then one member per distinct normalized form, which is what the
        // rollup counts its variants by: two members can mark the same slot
        // and still carry different values there, and `Server Reject` inside
        // `Server Busy` is the whole reason to distil at all.
        let mut seen: HashSet<u64> = HashSet::new();
        for (idx, line) in group.lines.iter().enumerate() {
            if seen.len() >= ROLLUP_DISTINCT_CAP {
                break;
            }
            if seen.insert(line.hash) {
                chosen.insert(idx);
            }
        }

        for idx in 0..group.lines.len() {
            if chosen.len() >= members {
                break;
            }
            chosen.insert(idx);
        }

        // Then a log-scaled sample spread evenly over the group's
        // occurrences, unioned with what is already chosen: 3 + ⌊log2 n⌋
        // members, at most 16. Enough that the fold visibly compresses and
        // the rollup fills; bounded so the distilled file stays a miniature
        // of the log, never a copy of it. Additive only — everything the
        // steps above already picked stays picked.
        let n = group.lines.len();
        let target = (3 + n.ilog2() as usize).min(16);
        for i in 0..target {
            chosen.insert(distill_sample_index(n, i, target));
        }

        self.distill_kept
            .extend(chosen.iter().filter_map(|i| group.member_line_nos.get(*i)));
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
            // The flush threshold bounds the *members* held in memory, not
            // a group's identity (lessence-940): keep the group retrievable
            // by a later exact-hash rejoin instead of emitting it now and
            // forgetting it ever existed. Only the modes that already never
            // evict, and --distill (which needs every member's raw line),
            // opt out; `retain_evicted_group` returns the group back on any
            // other reason it declined (chiefly the retention cap).
            let mut group = match self.retain_evicted_group(group) {
                Retention::Kept => return Ok(None),
                Retention::Declined(group) => group,
            };
            let formatted = self.format_group_dispatch(&mut group)?;
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

    /// Try to keep an evicted group's identity instead of emitting it right
    /// away (lessence-940). On success the group is moved into
    /// `self.retained`, keyed by its founding hash, with `lines` truncated
    /// to `[first, last]` and a seeded rollup accumulator in place of the
    /// member list the flush threshold exists to bound; the caller emits
    /// nothing now; a later exact or indexed similarity match rejoins it
    /// (`cluster_line_at`) and it is drained and formatted once, at
    /// `finish()`. Declines — handing `group` straight back — for
    /// --distill (needs every member's raw line to choose distilled
    /// samples) or once `RETAINED_TEMPLATE_CAP` is full — a hash already in
    /// `self.retained` can never reach this call (any line matching it
    /// would have rejoined in `cluster_line_at` before a buffer group with
    /// that founding hash could exist), so every insertion here is new.
    fn retain_evicted_group(&mut self, mut group: PatternGroup) -> Retention {
        if self.config.distill.is_some() {
            return Retention::Declined(group);
        }
        let key = group.first().hash;
        if !self.retained.contains_key(&key) && self.retained.len() >= RETAINED_TEMPLATE_CAP {
            self.json_retention_cap_hits += 1;
            return Retention::Declined(group);
        }
        let state = self.rollup_computer.seed(&group);
        let first = group.first().clone();
        group.lines = if group.count() <= 1 {
            vec![first]
        } else {
            vec![first, group.last().clone()]
        };
        group.retained = Some(state);
        if !self.retained.contains_key(&key) {
            self.retained_index.insert(group.first());
        }
        self.retained.insert(key, group);
        Retention::Kept
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
            let key = group.template().to_string();
            let count = group.count();
            // The summary shows original lines, so --sanitize-pii masks
            // the representative here, before any renderer sees it.
            let representative = if let Some(z) = &self.sanitizer {
                z.mask_line(&group.first().original, &group.first().tokens)
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

        // Explicit positive --top takes precedence over --fit. Otherwise
        // fit replaces the default cap; --top 0 disables only that cap.
        let (limit, was_capped, fit_truncated) = match (top_n, fit_budget) {
            (Some(n), _) if n > 0 => (n, false, 0),
            (_, Some(budget)) if total_patterns > budget => {
                let show = budget.saturating_sub(1);
                (show, false, total_patterns - show)
            }
            (Some(0), _) | (_, Some(_)) => (total_patterns, false, 0),
            _ => (DEFAULT_SUMMARY_CAP, total_patterns > DEFAULT_SUMMARY_CAP, 0),
        };
        sorted.truncate(limit);
        let display = sorted;

        Ok((display, total_patterns, was_capped, fit_truncated))
    }

    pub fn finish(&mut self) -> Result<Vec<String>> {
        // Constitutional compliance: Process any remaining batch
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        let mut output = Vec::new();

        // Every group still in the live buffer, plus every group retained
        // past its eviction (lessence-940) — each rendered exactly once,
        // here, since retention deliberately defers emission rather than
        // streaming a record per eviction. Sorted together by founding
        // position so output order stays chronological regardless of which
        // of the two a group came from, and deterministic across runs and
        // thread counts (`position` is assigned from input order, never
        // from processing order). The buffer and the retained map are
        // emptied below, so both hash indexes go with them.
        self.group_index.clear();
        let mut groups: Vec<PatternGroup> = std::mem::take(&mut self.buffer);
        groups.extend(std::mem::take(&mut self.retained).into_values());
        self.retained_index = retained_index::RetainedIndex::default();
        groups.sort_by_key(|group| group.position);
        let groups = self.merge_converged(groups);

        for mut group in groups {
            let formatted = self.format_group_dispatch(&mut group)?;
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

    /// Two lines can found separate groups — too unlike each other to fold
    /// when each arrived — and later converge on the same template as each
    /// accumulates members and its differing words become `<VARIES>`
    /// (lessence-682). Groups are compared to founders, never to each
    /// other, so nothing upstream notices. Identical template and anchor
    /// mean identical claim, and one claim is one line with one count:
    /// merge them here, at the one point every group passes through in
    /// founding order. `--distill` emits input lines, not groups, and keeps
    /// every member either way, so it is left alone.
    fn merge_converged(&self, groups: Vec<PatternGroup>) -> Vec<PatternGroup> {
        if self.config.distill.is_some() || groups.len() < 2 {
            return groups;
        }
        let mut by_claim: HashMap<(String, u64), usize> = HashMap::with_capacity(groups.len());
        let mut out: Vec<PatternGroup> = Vec::with_capacity(groups.len());
        for group in groups {
            let key = (group.template().to_string(), group.first().anchor);
            if let Some(&at) = by_claim.get(&key) {
                out[at].absorb(group, &self.rollup_computer);
            } else {
                by_claim.insert(key, out.len());
                out.push(group);
            }
        }
        out
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
                .then_with(|| a.1.template().cmp(b.1.template()))
        });

        let total_groups = groups_with_counts.len();
        let total_input_lines = self.stats.total_lines;

        // Take top N. The groups beyond N never pass through
        // `format_group_dispatch` (they're not rendered), so the briefing's
        // template map would silently miss them; record those directly here
        // so `sum(template_counts) == total_lines` holds regardless of
        // --top's cutoff.
        let mut top_groups: Vec<(usize, PatternGroup)> = Vec::with_capacity(n.min(total_groups));
        for (i, (count, group)) in groups_with_counts.into_iter().enumerate() {
            if i < n {
                top_groups.push((count, group));
            } else {
                let (first_epoch, last_epoch) = group_epoch_range(&group);
                self.stats.template_counts.record(
                    group.template(),
                    group.count(),
                    first_epoch,
                    last_epoch,
                );
            }
        }

        let lines_covered: usize = top_groups.iter().map(|(c, _)| c).sum();

        let mut output = Vec::new();
        for (count, mut group) in top_groups {
            let formatted = self.format_group_dispatch(&mut group)?;
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
        // does for all modes. --explain is exempted too: it is consumed
        // whole after the run by a machine, never streamed to a human
        // reader, so an evicted group re-forming later would emit one event
        // as several records with split counts (lessence-940) — a
        // fragmented count is a false premise, and the reader cannot merge
        // what it cannot detect.
        if self.config.summary || self.config.top_n.is_some() || self.config.explain {
            return false;
        }
        // Constitutional flush threshold: Use dynamic memory management instead of arbitrary limits
        // This maintains pattern detection quality while following "complete files in memory" principle
        const CONSTITUTIONAL_FLUSH_THRESHOLD: usize = 1000;
        self.buffer.len() > CONSTITUTIONAL_FLUSH_THRESHOLD
    }

    fn count_pattern_types(&mut self, tokens: &[Token]) {
        for token in tokens {
            let bucket = token.facts().stats_bucket;
            self.stats.bump(bucket);
            self.stats
                .cardinality
                .entry(bucket)
                .or_default()
                .insert(hash_token_value(token));
        }
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
        self.stats
            .record_briefing_line(&normalized_line.tokens, &normalized_line.original);
        self.stats.record_span(&normalized_line.tokens);

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

// Keep the rounding and bounds clamp together: at large n, floating-point
// rounding can put the final sample one past the group's last index.
fn distill_sample_index(n: usize, i: usize, target: usize) -> usize {
    let idx = ((i * (n - 1)) as f64 / (target - 1) as f64).round() as usize;
    idx.min(n - 1)
}

mod render;
mod retained_index;

#[cfg(test)]
mod tests;
