use crate::run_metadata::{Count, InputCompleteness, InputFacts, RunMetadata};
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

pub fn apply_pii_masking(original: &str, tokens: &[Token]) -> String {
    Sanitizer::legacy().mask_line(original, tokens)
}

use crate::sanitize::{CREDENTIAL_ASSIGNMENT, JWT, PROVIDER_KEY, Sanitizer};

const MIN_CREDENTIAL_VALUE: usize = 6;

fn is_credential_value(text: &str, match_start: usize, value: &str) -> bool {
    let bare = value
        .strip_prefix(['"', '\''])
        .and_then(|v| v.strip_suffix(['"', '\'']))
        .unwrap_or(value);
    bare.len() >= MIN_CREDENTIAL_VALUE && !key_is_a_url_path_segment(text, match_start)
}

fn key_is_a_url_path_segment(text: &str, key_start: usize) -> bool {
    text[..key_start].ends_with('/')
}

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
    template: String,
    position: usize,
    first_line_no: usize,
    last_line_no: usize,
    first_source_id: SourceId,
    last_source_id: SourceId,
    nearest: Option<Nearest>,
    member_line_nos: Vec<usize>,
    count: usize,
    retained: Option<RetainedState>,
    slot_units: Option<Vec<(usize, usize)>>,
    timeline: timeline::Timeline,
}

#[derive(Debug, Default)]
struct RetainedState {
    per_type: PerType,
    varies: SlotCounts,
    positional_members: usize,
    realign: BTreeMap<String, usize>,
    realign_capped: bool,
    slot_widened_after_counting: bool,
}

impl RetainedState {
    fn varies_counts_known(&self) -> bool {
        !self.realign_capped && !self.slot_widened_after_counting
    }
}

#[derive(Debug)]
struct TypeValues {
    values: Accumulator,
    capped: bool,
}

type PerType = BTreeMap<&'static str, TypeValues>;

#[derive(Debug, Default)]
struct VariesCounts {
    counts: HashMap<String, usize>,
    capped: bool,
    ceiling: Option<(u64, String)>,
}

type SlotCounts = Vec<VariesCounts>;

fn slot_mut(slots: &mut SlotCounts, i: usize) -> &mut VariesCounts {
    if slots.len() <= i {
        slots.resize_with(i + 1, VariesCounts::default);
    }
    &mut slots[i]
}

impl VariesCounts {
    fn rank(value: &str) -> u64 {
        fnv1a(value.as_bytes())
    }

    fn add(&mut self, value: &str, n: usize, cap: usize) {
        if let Some(count) = self.counts.get_mut(value) {
            *count += n;
            return;
        }
        if self.counts.len() < cap {
            self.counts.insert(value.to_string(), n);
            return;
        }
        self.capped = true;
        if self.ceiling.is_none() {
            self.ceiling = self
                .counts
                .keys()
                .map(|held| (Self::rank(held), held))
                .max()
                .map(|(rank, held)| (rank, held.clone()));
        }
        let Some((rank, held)) = &self.ceiling else {
            return;
        };
        if (Self::rank(value), value) >= (*rank, held.as_str()) {
            return;
        }
        let (_, out) = self.ceiling.take().expect("checked above");
        self.counts.remove(&out);
        self.counts.insert(value.to_string(), n);
    }
}

fn first_diff(line: &LogLine, rep: &LogLine, sanitizer: Option<&Sanitizer>) -> Option<FirstDiff> {
    let (ours, theirs) = first_diff_ranges(&line.normalized, &rep.normalized)?;
    Some(match sanitizer {
        None => FirstDiff {
            at: ours.start,
            ours: line.normalized[ours].to_string(),
            theirs: rep.normalized[theirs].to_string(),
        },
        Some(z) => {
            let (ours, at) = z.mask_range(&line.normalized, &line.tokens, ours);
            let (theirs, _) = z.mask_range(&rep.normalized, &rep.tokens, theirs);
            FirstDiff { ours, theirs, at }
        }
    })
}

fn first_diff_ranges(
    line: &str,
    rep: &str,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let span = |text: &str, word: &str| {
        let at = word.as_ptr() as usize - text.as_ptr() as usize;
        at..at + word.len()
    };
    let ours = line.split_whitespace();
    let theirs = rep.split_whitespace();
    for (a, b) in ours.zip(theirs) {
        if a != b {
            return Some((span(line, a), span(rep, b)));
        }
    }
    let ours: Vec<&str> = line.split_whitespace().collect();
    let theirs: Vec<&str> = rep.split_whitespace().collect();
    match ours.len().cmp(&theirs.len()) {
        std::cmp::Ordering::Greater => Some((span(line, ours[theirs.len()]), rep.len()..rep.len())),
        std::cmp::Ordering::Less => Some((line.len()..line.len(), span(rep, theirs[ours.len()]))),
        std::cmp::Ordering::Equal => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Nearest {
    pub group_line_no: usize,
    pub score: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub anchor_mismatch: bool,
    pub first_diff: Option<FirstDiff>,
}

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
            slot_units: None,
            timeline: timeline::Timeline::default(),
        }
    }

    #[cfg(test)]
    fn add_line(&mut self, line: LogLine, line_no: usize) {
        let edits = self.edits_for(&line).unwrap_or_default();
        self.add_line_at(line, LineLocation::new(SourceId::STDIN, line_no), &edits);
    }

    #[cfg(test)]
    fn rejoin(
        &mut self,
        line: LogLine,
        line_no: usize,
        rollup_computer: &RollupComputer,
        min_collapse: usize,
    ) {
        let edits = self.edits_for(&line).unwrap_or_default();
        let location = LineLocation::new(SourceId::STDIN, line_no);
        self.retained_rejoin(line, location, &edits, rollup_computer, min_collapse);
    }

    fn edits_for(&self, line: &LogLine) -> Option<Vec<Edit>> {
        if line.hash == self.first().hash {
            return Some(Vec::new());
        }
        template_edits(&self.template, &line.normalized)
    }

    fn add_line_at(&mut self, line: LogLine, location: LineLocation, edits: &[Edit]) {
        self.apply_template_edits(edits);
        self.assert_claim_holds(&line.normalized);
        self.lines.push(line);
        self.last_line_no = location.line_no;
        self.last_source_id = location.source_id;
        self.count += 1;
        self.assert_members_held();
    }

    fn retained_rejoin(
        &mut self,
        line: LogLine,
        location: LineLocation,
        edits: &[Edit],
        rollup_computer: &RollupComputer,
        min_collapse: usize,
    ) {
        let line_units = unit_spans(&line.normalized);
        let mut template_units = unit_spans(&self.template);
        if !edits.is_empty() {
            if let Some(state) = &mut self.retained {
                rollup_computer.accumulate_new_varies(
                    &self.template,
                    &template_units,
                    edits,
                    state,
                );
            }
            self.apply_template_edits(edits);
            template_units = self
                .slot_units
                .clone()
                .expect("a template with edits applied has slot units");
        }
        self.assert_claim_holds(&line.normalized);
        let held_every_member = self.holds_every_member();
        self.count += 1;
        self.last_line_no = location.line_no;
        self.last_source_id = location.source_id;
        if let Some(state) = &mut self.retained {
            rollup_computer.accumulate_tokens(std::slice::from_ref(&line), &mut state.per_type);
            let template = VariesSlots::new(&self.template, &template_units);
            rollup_computer.accumulate_retained_varies(&line, &line_units, &template, state);
        }
        if held_every_member {
            self.lines.push(line);
            if self.count >= min_collapse && self.lines.len() > 2 {
                let last = self.lines.pop().expect("pushed above");
                self.lines.truncate(1);
                self.lines.push(last);
            }
        } else {
            self.lines[1] = line;
        }
        self.assert_members_held();
    }

    fn holds_every_member(&self) -> bool {
        self.lines.len() == self.count
    }

    fn assert_members_held(&self) {
        debug_assert!(
            self.holds_every_member() || (1..=2).contains(&self.lines.len()),
            "a group holds every member or only its first and last: {} held of {}",
            self.lines.len(),
            self.count
        );
    }

    fn absorb(
        &mut self,
        mut other: PatternGroup,
        rollup_computer: &RollupComputer,
        min_collapse: usize,
    ) {
        debug_assert_eq!(self.template, other.template);
        self.count += other.count;
        self.timeline.absorb(std::mem::take(&mut other.timeline));
        let other_is_later = other.last_line_no > self.last_line_no
            || (other.last_line_no == self.last_line_no && other.position > self.position);
        if other_is_later {
            self.last_line_no = other.last_line_no;
            self.last_source_id = other.last_source_id;
        }

        let all_held = self.count < min_collapse;
        if all_held || (self.retained.is_none() && other.retained.is_none()) {
            if all_held {
                self.retained = None;
            }
            let own_last = self.lines.pop().unwrap();
            let mut other_lines = other.lines;
            if other_is_later {
                self.lines.push(own_last);
                self.lines.append(&mut other_lines);
            } else {
                self.lines.append(&mut other_lines);
                self.lines.push(own_last);
            }
            self.assert_members_held();
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
            let template = VariesSlots::new(&self.template, &unit_spans(&self.template));
            for line in &other.lines {
                let line_units = unit_spans(&line.normalized);
                rollup_computer.accumulate_retained_varies(line, &line_units, &template, state);
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
        self.assert_members_held();
    }

    fn apply_template_edits(&mut self, edits: &[Edit]) {
        if edits.is_empty() {
            return;
        }
        apply_edits(&mut self.template, edits);
        self.slot_units = Some(unit_spans(&self.template));
    }

    fn joins_through_slots(
        &self,
        line: &LogLine,
        line_units: &mut Option<Vec<(usize, usize)>>,
        threshold: u8,
    ) -> bool {
        self.slot_units.as_ref().is_some_and(|units| {
            line.anchor == self.first().anchor
                && first_difference_may_vary(&self.template, &line.normalized)
                && joins_through_slots(
                    &self.template,
                    units,
                    &line.normalized,
                    line_units.get_or_insert_with(|| unit_spans(&line.normalized)),
                    threshold,
                )
        })
    }

    fn assert_claim_holds(&self, joined: &str) {
        debug_assert!(
            template_holds(&self.template, joined),
            "the template does not hold for the line that joined:\n  template: {}\n  joined:   {joined}",
            self.template
        );
        debug_assert!(
            template_holds(&self.template, &self.lines[0].normalized),
            "the template no longer holds for the group's first line:\n  template: {}\n  first:    {}",
            self.template,
            self.lines[0].normalized
        );
    }

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
    pub(super) sanitizer: Option<Sanitizer>,
    config: Config,
    normalizer: Normalizer,
    detection: LineDetection,
    buffer: Vec<PatternGroup>,
    group_index: ahash::AHashMap<u64, usize>,
    stats: FoldingStats,
    position_counter: usize,
    batch_buffer: Vec<String>,
    batch_locations: Vec<LineLocation>,
    sources: Vec<String>,
    markdown_entries: Vec<String>,
    next_json_id: usize,
    input_facts: InputFacts,
    json_groups_emitted: usize,
    json_groups_total: Option<usize>,
    json_omitted_by_top: usize,
    json_omitted_by_summary_cap: usize,
    json_omitted_by_fit: usize,
    json_capped_entries: usize,
    json_uncomputed_variation_groups: usize,
    json_sampled_entries: usize,
    json_omitted_values_lower_bound: usize,
    rollup_computer: RollupComputer,
    distill_groups: Vec<DistillGroup>,
    retained: ahash::AHashMap<u64, PatternGroup>,
    retained_index: retained_index::RetainedIndex,
    json_retention_cap_hits: usize,
}

enum LineDetection {
    Inline,
    GlobalPool,
    SizedPool(rayon::ThreadPool),
}

enum Retention {
    Kept,
    Declined(Box<PatternGroup>),
}

pub const RETAINED_TEMPLATE_CAP: usize = 16_384;

const BATCH_LINES: usize = 10_000;

const LIVE_GROUP_LIMIT: usize = 1000;

const EVICTION_DISTANCE: usize = 100;

pub const TOP_SHOWS_EVERY_GROUP: usize = 0;

#[derive(Debug, Default)]
pub struct FoldingStats {
    pub total_lines: usize,
    pub continuation_lines_absorbed: usize,
    pub output_lines: usize,
    pub collapsed_groups: usize,
    pub lines_saved: usize,
    pub patterns_detected: usize,
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
    pub numbers: usize,
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
    pub(crate) timeline_grid: Option<crate::briefing::Grid>,
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

    fn record_span(&mut self, tokens: &[Token]) -> Option<i64> {
        let ts = first_timestamp_in(tokens)?;
        if self.span_first.is_none() {
            self.span_first = Some(ts.clone());
        }
        let epoch = crate::briefing::epoch_seconds(&ts);
        if let Some(epoch) = epoch {
            self.histogram.record(epoch);
        }
        self.span_last = Some(ts);
        epoch
    }

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
            ("numbers", StatsBucket::Numbers, self.numbers),
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

    fn cardinality_for(&self, bucket: StatsBucket) -> (u64, bool) {
        self.cardinality
            .get(&bucket)
            .map_or((0, true), |c| (c.distinct(), c.is_exact()))
    }
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
            StatsBucket::Numbers => self.numbers += 1,
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
            numbers: self.numbers,
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
    numbers: usize,
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

#[derive(Serialize)]
struct LineRef {
    source: Option<String>,
    line: String,
    line_no: usize,
}

#[derive(Serialize)]
struct TimeRange {
    first_seen: Option<String>,
    last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    buckets: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bunched: Option<timeline::Bunched>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "group")]
struct GroupRecord {
    id: usize,
    count: usize,
    token_types: Vec<&'static str>,
    normalized: String,
    first: LineRef,
    last: LineRef,
    time_range: TimeRange,
    variation: GroupRollup,
    #[serde(skip_serializing_if = "Option::is_none")]
    nearest: Option<Nearest>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "summary")]
struct SummaryRecord {
    #[serde(flatten)]
    stats: StatsJson,
    #[serde(flatten)]
    metadata: RunMetadata,
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
struct GroupCompleteness {
    complete: bool,
    emitted: usize,
    total: Count,
    omitted_by_top: Count,
    omitted_by_summary_cap: Count,
    omitted_by_fit: Count,
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

fn token_type_name(token: &Token) -> &'static str {
    token.facts().machine_name
}

fn first_timestamp_in(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|t| match t {
        Token::Timestamp(s) => Some(s.clone()),
        _ => None,
    })
}

fn group_epoch_range(group: &PatternGroup) -> (Option<i64>, Option<i64>) {
    let first = first_timestamp_in(&group.first().tokens)
        .as_deref()
        .and_then(crate::briefing::epoch_seconds);
    let last = first_timestamp_in(&group.last().tokens)
        .as_deref()
        .and_then(crate::briefing::epoch_seconds);
    (first, last)
}

const ROLLUP_K: usize = 7;

pub const ROLLUP_DISTINCT_CAP: usize = 64;

pub const DISTILL_FORMS: usize = 6;

pub(crate) const DISTILL_CHEAP_LINE_BYTES: usize = 512;

pub(crate) struct DistillGroup {
    pub template: String,
    pub token_types: Vec<&'static str>,
    pub all_types: Vec<&'static str>,
    pub anchor: u64,
    pub avg_bytes: usize,
    pub kept: Vec<usize>,
    pub capping_extra: Vec<usize>,
    pub count: usize,
    pub distinct_forms: usize,
}

const ROLLUP_TEXT_SAMPLE_THRESHOLD: usize = 3;

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(into = "JsonVariationEntry")]
struct VariationEntry {
    pub distinct_count: usize,
    pub samples: Vec<String>,
    pub capped: bool,
    pub counts: Option<Vec<usize>>,
    pub slots: Option<Vec<VariationEntry>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    slots: Option<Vec<JsonVariationEntry>>,
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
            slots: entry
                .slots
                .map(|slots| slots.into_iter().map(Self::from).collect()),
        }
    }
}

type GroupRollup = BTreeMap<&'static str, VariationEntry>;

fn is_sample_worthy(token: &Token) -> bool {
    token.facts().sample_worthy
}

fn token_value_string(token: &Token) -> String {
    token.value_string()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    fnv1a_fold(&mut h, bytes);
    h
}

fn fnv1a_fold(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= u64::from(b);
        *h = h.wrapping_mul(FNV_PRIME);
    }
}

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

pub(super) const VARIES: &str = "VARIES";
pub(crate) const VARIES_MARK: &str = "<VARIES>";
const ABSENT: &str = "∅";

pub(super) fn template_holds(template: &str, member: &str) -> bool {
    shows_every_unit(template, member) || reads_as(template, member)
}

fn shows_every_unit(template: &str, member: &str) -> bool {
    let words: Vec<&str> = unit_spans(member)
        .iter()
        .map(|&(at, len)| &member[at..at + len])
        .collect();
    let n = words.len();
    let mut read_shows_from = vec![false; n + 1];
    read_shows_from[n] = true;
    let mut unit_shows_from = vec![false; n + 1];
    for &(at, len) in unit_spans(template).iter().rev() {
        let unit = &template[at..at + len];
        if unit == VARIES_MARK {
            bare_slot_shows(&read_shows_from, &mut unit_shows_from);
        } else if let Some((first, last)) = unit.find(VARIES_MARK).zip(unit.rfind(VARIES_MARK)) {
            let (before, after) = (&unit[..first], &unit[last + VARIES_MARK.len()..]);
            slot_with_text_shows(
                &words,
                before,
                after,
                &read_shows_from,
                &mut unit_shows_from,
            );
        } else {
            literal_shows(&words, unit, &read_shows_from, &mut unit_shows_from);
        }
        std::mem::swap(&mut read_shows_from, &mut unit_shows_from);
    }
    read_shows_from[0]
}

fn bare_slot_shows(read_shows_from: &[bool], unit_shows_from: &mut [bool]) {
    let n = read_shows_from.len() - 1;
    unit_shows_from[n] = read_shows_from[n];
    for j in (0..n).rev() {
        unit_shows_from[j] = read_shows_from[j] || unit_shows_from[j + 1];
    }
}

fn slot_with_text_shows(
    words: &[&str],
    before: &str,
    after: &str,
    read_shows_from: &[bool],
    unit_shows_from: &mut [bool],
) {
    let n = words.len();
    let mut later = false;
    unit_shows_from[n] = false;
    for j in (0..n).rev() {
        let word = words[j];
        let ends_here = word.len() >= before.len() + after.len()
            && word.ends_with(after)
            && read_shows_from[j + 1];
        unit_shows_from[j] = word.starts_with(before) && (ends_here || later);
        later |= word.ends_with(after) && read_shows_from[j + 1];
    }
}

fn literal_shows(
    words: &[&str],
    unit: &str,
    read_shows_from: &[bool],
    unit_shows_from: &mut [bool],
) {
    let n = words.len();
    unit_shows_from[n] = false;
    for j in (0..n).rev() {
        unit_shows_from[j] = words[j] == unit && read_shows_from[j + 1];
    }
}

fn reads_as(template: &str, member: &str) -> bool {
    let mut parts = template.split(VARIES_MARK);
    let Some(mut rest) = member.strip_prefix(parts.next().unwrap_or("")) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

const MAX_PLAIN_WORD_DIFFS: usize = 1;

const MAX_ALIGN_WORDS: usize = 256;

const ALIGN_BAND: usize = 8;

fn alignable(left: usize, right: usize) -> bool {
    left == right
        || (left <= MAX_ALIGN_WORDS && right <= MAX_ALIGN_WORDS)
        || left.abs_diff(right) <= ALIGN_BAND
}

pub(super) fn align_words(left: &[&str], right: &[&str]) -> Vec<Option<usize>> {
    if left.len() == right.len() || !alignable(left.len(), right.len()) {
        return (0..left.len())
            .map(|i| (i < right.len()).then_some(i))
            .collect();
    }
    if left.len() > MAX_ALIGN_WORDS || right.len() > MAX_ALIGN_WORDS {
        return align_banded(left, right, ALIGN_BAND);
    }
    align_exact(left, right)
}

fn align_exact(left: &[&str], right: &[&str]) -> Vec<Option<usize>> {
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
    out
}

const OUTSIDE_BAND: i32 = -1;

struct Band {
    low: isize,
    width: usize,
    cols: usize,
}

impl Band {
    fn new(rows: usize, cols: usize, band: usize) -> Self {
        Self {
            low: cols.min(rows) as isize - rows as isize - band as isize,
            width: rows.abs_diff(cols) + 2 * band + 1,
            cols,
        }
    }

    fn diagonal(&self, i: usize, j: usize) -> Option<usize> {
        let k = j as isize - i as isize - self.low;
        (0..self.width as isize).contains(&k).then_some(k as usize)
    }

    fn cell_in_row(&self, i: usize, j: usize) -> usize {
        debug_assert!(self.columns(i).contains(&j));
        (j as isize - i as isize - self.low) as usize
    }

    fn columns(&self, i: usize) -> std::ops::RangeInclusive<usize> {
        let first = (i as isize + self.low).max(0) as usize;
        let last =
            (i as isize + self.low + self.width as isize - 1).min(self.cols as isize) as usize;
        first..=last
    }
}

fn align_banded(left: &[&str], right: &[&str], band: usize) -> Vec<Option<usize>> {
    let (rows, cols) = (left.len(), right.len());
    debug_assert!(rows.abs_diff(cols) <= band && (rows != cols || band > 0));
    let band = Band::new(rows, cols, band);
    let width = band.width;
    let mut below = vec![OUTSIDE_BAND; width];
    let mut here = vec![OUTSIDE_BAND; width];
    for j in band.columns(rows) {
        below[band.cell_in_row(rows, j)] = 0;
    }
    let mut down = vec![0u64; (rows * width).div_ceil(64)];
    let value =
        |row: &[i32], i: usize, j: usize| band.diagonal(i, j).map_or(OUTSIDE_BAND, |k| row[k]);
    for i in (0..rows).rev() {
        here.fill(OUTSIDE_BAND);
        for j in band.columns(i).rev() {
            let k = band.cell_in_row(i, j);
            here[k] = if j == cols {
                0
            } else if left[i] == right[j] {
                value(&below, i + 1, j + 1) + 1
            } else {
                let (drop_left, drop_right) = (value(&below, i + 1, j), value(&here, i, j + 1));
                if drop_left >= drop_right {
                    let bit = i * width + k;
                    down[bit / 64] |= 1 << (bit % 64);
                }
                drop_left.max(drop_right)
            };
        }
        std::mem::swap(&mut below, &mut here);
    }
    let mut out = vec![None; rows];
    let (mut i, mut j) = (0, 0);
    while i < rows && j < cols {
        if left[i] == right[j] {
            out[i] = Some(j);
            i += 1;
            j += 1;
        } else {
            let bit = i * width + band.diagonal(i, j).expect("the walk stays inside the band");
            if (down[bit / 64] >> (bit % 64)) & 1 == 1 {
                i += 1;
            } else {
                j += 1;
            }
        }
    }
    out
}

fn is_field_delimiter(b: u8) -> bool {
    matches!(b, b'=' | b':' | b'[' | b'(')
}

fn is_closing_bracket(b: u8) -> bool {
    matches!(b, b']' | b')')
}

fn after_last_field_delimiter(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&b| is_field_delimiter(b))
        .map_or(0, |i| i + 1)
}

fn shared_affixes(r: &str, w: &str) -> (usize, usize) {
    let (rb, wb) = (r.as_bytes(), w.as_bytes());
    let common = rb.iter().zip(wb).take_while(|(x, y)| x == y).count();
    let common = common.min(r.len() - 1).min(w.len() - 1);
    let prefix = after_last_field_delimiter(&rb[..common]);
    let mut suffix = 0;
    while prefix + suffix + 1 < rb.len()
        && prefix + suffix + 1 < wb.len()
        && rb[rb.len() - 1 - suffix] == wb[wb.len() - 1 - suffix]
        && is_closing_bracket(rb[rb.len() - 1 - suffix])
    {
        suffix += 1;
    }
    (prefix, suffix)
}

fn kept_affixes(prefix: &str, suffix: &str, w: &str) -> (usize, usize) {
    let (pb, sb, wb) = (prefix.as_bytes(), suffix.as_bytes(), w.as_bytes());
    let common = pb.iter().zip(wb).take_while(|(x, y)| x == y).count();
    let p = if common == pb.len() && wb.len() > pb.len() {
        pb.len()
    } else {
        let common = common.min(wb.len().saturating_sub(1));
        after_last_field_delimiter(&pb[..common])
    };
    let mut q = 0;
    while q < sb.len() && p + q + 1 < wb.len() && sb[sb.len() - 1 - q] == wb[wb.len() - 1 - q] {
        q += 1;
    }
    (p, q)
}

fn unpaired_quote(r: &str, from: usize, to: usize) -> bool {
    let b = r.as_bytes();
    let (mut every, mut unescaped) = (0usize, 0usize);
    for (i, &c) in b.iter().enumerate().take(to).skip(from) {
        if c == b'"' {
            every += 1;
            if i == 0 || b[i - 1] != b'\\' {
                unescaped += 1;
            }
        }
    }
    every % 2 == 1 || unescaped % 2 == 1
}

fn balance_quotes(r: &str, w: &str, p: usize, q: usize) -> (usize, usize) {
    if !unpaired_quote(r, p, r.len() - q) {
        return (p, q);
    }
    closing_quote_joins_suffix(r, w, p, q)
        .or_else(|| opening_quote_joins_prefix(r, w, p, q))
        .unwrap_or_else(|| slot_covers_quoted_value(r, p, q))
}

fn closing_quote_joins_suffix(r: &str, w: &str, p: usize, q: usize) -> Option<(usize, usize)> {
    let odd = |p: usize, q: usize| unpaired_quote(r, p, r.len() - q);
    let (rb, wb) = (r.as_bytes(), w.as_bytes());
    let mut inner = q;
    while let Some(quote) = r[p..r.len() - inner].rfind('"').map(|at| p + at) {
        let quote = if quote > p && rb[quote - 1] == b'\\' {
            quote - 1
        } else {
            quote
        };
        let keep = r.len() - quote;
        if quote == p || wb.len() <= p + keep || !w.ends_with(&r[quote..]) {
            return None;
        }
        inner = keep;
        if !odd(p, inner) {
            while p + inner + 1 < rb.len()
                && p + inner + 1 < wb.len()
                && rb[rb.len() - 1 - inner] == wb[wb.len() - 1 - inner]
                && is_closing_bracket(rb[rb.len() - 1 - inner])
            {
                inner += 1;
            }
            return Some((p, inner));
        }
    }
    None
}

fn opening_quote_joins_prefix(r: &str, w: &str, p: usize, q: usize) -> Option<(usize, usize)> {
    let odd = |p: usize, q: usize| unpaired_quote(r, p, r.len() - q);
    let wb = w.as_bytes();
    let mut inner = p;
    while let Some(quote) = r[inner..r.len() - q].find('"').map(|at| inner + at) {
        let keep = quote + 1;
        if keep >= r.len() - q || wb.len() <= keep + q || !w.starts_with(&r[..keep]) {
            return None;
        }
        inner = keep;
        if !odd(inner, q) {
            return Some((inner, q));
        }
    }
    None
}

fn slot_covers_quoted_value(r: &str, p: usize, q: usize) -> (usize, usize) {
    let odd = |p: usize, q: usize| unpaired_quote(r, p, r.len() - q);
    let mut outer = p;
    while odd(outer, q) {
        let Some(quote) = r[..outer].rfind('"') else {
            break;
        };
        outer = after_last_field_delimiter(&r.as_bytes()[..quote]);
    }
    if !odd(outer, q) {
        (outer, q)
    } else if !odd(outer, 0) {
        (outer, 0)
    } else {
        (p, q)
    }
}

fn slot_affix(r: &str) -> Option<(&str, &str)> {
    let k = r.find(VARIES_MARK)?;
    Some((&r[..k], &r[k + VARIES_MARK.len()..]))
}

type MemberUnits = (usize, usize);

#[derive(Debug, PartialEq)]
struct UnshownRun {
    before_unit: usize,
    member_units: MemberUnits,
}

#[derive(Debug, Default, PartialEq)]
struct UnitRanges {
    stands_for: Vec<Option<MemberUnits>>,
    unshown: Vec<UnshownRun>,
}

fn unit_ranges(tmpl: &[&str], mem: &[&str], aligned: &[Option<usize>]) -> UnitRanges {
    fn resolve(
        tmpl: &[&str],
        mem: &[&str],
        (t0, t1): (usize, usize),
        (m0, m1): MemberUnits,
        out: &mut [Option<MemberUnits>],
        unshown: &mut Vec<UnshownRun>,
    ) {
        if t0 == t1 {
            if m0 < m1 {
                unshown.push(UnshownRun {
                    before_unit: t0,
                    member_units: (m0, m1),
                });
            }
            return;
        }
        if m0 == m1 {
            out[t0..t1].fill(Some((m0, m0)));
        } else if t1 - t0 == 1 {
            out[t0] = Some((m0, m1));
        } else if t1 - t0 == m1 - m0 {
            for (i, j) in (t0..t1).zip(m0..m1) {
                out[i] = Some((j, j + 1));
            }
        } else {
            let anchor = (t0..t1).find_map(|i| {
                let (prefix, suffix) = slot_affix(tmpl[i])
                    .filter(|(prefix, suffix)| !prefix.is_empty() || !suffix.is_empty())?;
                (m0..m1)
                    .find(|&j| kept_affixes(prefix, suffix, mem[j]) == (prefix.len(), suffix.len()))
                    .map(|j| (i, j))
            });
            if let Some((i, j)) = anchor {
                out[i] = Some((j, j + 1));
                resolve(tmpl, mem, (t0, i), (m0, j), out, unshown);
                resolve(tmpl, mem, (i + 1, t1), (j + 1, m1), out, unshown);
            } else if tmpl[t0..t1].iter().all(|&r| r == VARIES_MARK) {
                read_in_order_into_bare_slots((t0, t1), (m0, m1), out);
            }
        }
    }
    let mut out: Vec<Option<MemberUnits>> = aligned.iter().map(|a| a.map(|j| (j, j + 1))).collect();
    let mut unshown = Vec::new();
    let mut i = 0;
    let mut from = 0;
    while i < aligned.len() {
        if let Some(j) = aligned[i] {
            if from < j {
                unshown.push(UnshownRun {
                    before_unit: i,
                    member_units: (from, j),
                });
            }
            from = j + 1;
            i += 1;
            continue;
        }
        let start = i;
        while i < aligned.len() && aligned[i].is_none() {
            i += 1;
        }
        let to = aligned
            .get(i)
            .copied()
            .flatten()
            .unwrap_or(mem.len())
            .max(from);
        resolve(tmpl, mem, (start, i), (from, to), &mut out, &mut unshown);
        from = to;
    }
    if from < mem.len() {
        unshown.push(UnshownRun {
            before_unit: aligned.len(),
            member_units: (from, mem.len()),
        });
    }
    UnitRanges {
        stands_for: out,
        unshown,
    }
}

fn read_in_order_into_bare_slots(
    (t0, t1): (usize, usize),
    (m0, m1): MemberUnits,
    out: &mut [Option<MemberUnits>],
) {
    for (n, i) in (t0..t1).enumerate() {
        let from = (m0 + n).min(m1);
        let to = if i + 1 == t1 { m1 } else { (from + 1).min(m1) };
        out[i] = Some((from, to));
    }
}

fn range_text<'m>(member: &'m str, spans: &[(usize, usize)], (c, d): (usize, usize)) -> &'m str {
    if c == d {
        return "";
    }
    let (start, _) = spans[c];
    let (at, len) = spans[d - 1];
    &member[start..at + len]
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Edit {
    Vary {
        at: usize,
        len: usize,
    },
    Open {
        at: usize,
        unit_with_separator: String,
    },
}

fn template_edits(template: &str, member: &str) -> Option<Vec<Edit>> {
    let spans = unit_spans(template);
    let member_spans = unit_spans(member);
    let tmpl: Vec<&str> = spans
        .iter()
        .map(|&(at, len)| &template[at..at + len])
        .collect();
    let mem: Vec<&str> = member_spans
        .iter()
        .map(|&(at, len)| &member[at..at + len])
        .collect();
    if !alignable(tmpl.len(), mem.len()) {
        return None;
    }
    let aligned = align_words(&tmpl, &mem);
    let UnitRanges {
        stands_for: ranges,
        unshown,
    } = if tmpl.len() == mem.len() {
        UnitRanges::default()
    } else {
        unit_ranges(&tmpl, &mem, &aligned)
    };
    let mut unshown = unshown.into_iter().peekable();
    let mut edits = Vec::new();
    let mut shared_atoms = SharedAtoms::new(template, member);
    for i in 0..=spans.len() {
        while let Some(run) = unshown.next_if(|run| run.before_unit == i) {
            edits.push(slot_opening(
                template,
                &spans,
                member,
                &member_spans,
                i,
                run.member_units,
            )?);
        }
        let Some(&(at, len)) = spans.get(i) else {
            break;
        };
        let r = tmpl[i];
        if aligned[i].is_some_and(|j| mem[j] == r) {
            continue;
        }
        if let Some((prefix, suffix)) = slot_affix(r) {
            if prefix.is_empty() && suffix.is_empty() {
                continue;
            }
            let range = match aligned[i] {
                Some(j) => Some((j, j + 1)),
                None => ranges[i],
            };
            let (p, q) = range.map_or((0, 0), |range| {
                let w = range_text(member, &member_spans, range);
                let (p, q) = kept_affixes(prefix, suffix, w);
                let (p, q) = balance_quotes(r, w, p, q);
                (p.min(prefix.len()), q.min(suffix.len()))
            });
            if p < prefix.len() || q < suffix.len() {
                edits.push(Edit::Vary {
                    at: at + p,
                    len: len - p - q,
                });
            }
            continue;
        }
        if shared_atoms.keeps(r) {
            continue;
        }
        let partner = aligned[i].or_else(|| match ranges.get(i).copied().flatten() {
            Some((c, d)) if d == c + 1 => Some(c),
            _ => None,
        });
        let (p, q) = partner.map_or((0, 0), |j| {
            let (p, q) = shared_affixes(r, mem[j]);
            balance_quotes(r, mem[j], p, q)
        });
        edits.push(Edit::Vary {
            at: at + p,
            len: len - p - q,
        });
    }
    Some(edits)
}

struct SharedAtoms<'a> {
    template: &'a str,
    member: &'a str,
    same_pci_addresses: Option<bool>,
    same_option_names: Option<bool>,
}

impl<'a> SharedAtoms<'a> {
    fn new(template: &'a str, member: &'a str) -> Self {
        Self {
            template,
            member,
            same_pci_addresses: None,
            same_option_names: None,
        }
    }

    fn keeps(&mut self, unit: &str) -> bool {
        use crate::normalize::{cli_option_names, pci_addresses};
        let (template, member) = (self.template, self.member);
        (is_whole_atom(pci_addresses(unit), unit)
            && *self
                .same_pci_addresses
                .get_or_insert_with(|| same_atoms(pci_addresses(template), pci_addresses(member))))
            || (is_whole_atom(cli_option_names(unit), unit)
                && *self.same_option_names.get_or_insert_with(|| {
                    same_atoms(cli_option_names(template), cli_option_names(member))
                }))
    }
}

fn is_whole_atom<'s>(mut atoms: impl Iterator<Item = regex::Match<'s>>, unit: &str) -> bool {
    atoms
        .next()
        .is_some_and(|m| m.start() == 0 && m.end() == unit.len())
}

fn same_atoms<'s>(
    ours: impl Iterator<Item = regex::Match<'s>>,
    theirs: impl Iterator<Item = regex::Match<'s>>,
) -> bool {
    ours.map(|m| m.as_str()).eq(theirs.map(|m| m.as_str()))
}

fn slot_opening(
    template: &str,
    spans: &[(usize, usize)],
    member: &str,
    member_spans: &[(usize, usize)],
    t: usize,
    (m0, m1): (usize, usize),
) -> Option<Edit> {
    if spans.is_empty() {
        return None;
    }
    let gap = |units: &[(usize, usize)], len: usize, i: usize| {
        let from = i.checked_sub(1).map_or(0, |b| units[b].0 + units[b].1);
        let to = units.get(i).map_or(len, |&(at, _)| at);
        (i == 0 || i == units.len() || from < to).then_some(from..to)
    };
    let between = gap(spans, template.len(), t)?;
    let before = &member[gap(member_spans, member.len(), m0)?];
    let after = &member[gap(member_spans, member.len(), m1)?];
    let text = &template[between.clone()];
    let parts_apart = (t == 0 || !before.is_empty()) && (t == spans.len() || !after.is_empty());
    Some(if parts_apart && text.strip_prefix(before) == Some(after) {
        Edit::Open {
            at: between.start + before.len(),
            unit_with_separator: VARIES_MARK.to_string(),
        }
    } else if t == 0 {
        Edit::Open {
            at: between.end,
            unit_with_separator: format!(
                "{VARIES_MARK}{}",
                if after.is_empty() { " " } else { after }
            ),
        }
    } else {
        Edit::Open {
            at: between.start,
            unit_with_separator: format!(
                "{}{VARIES_MARK}",
                if before.is_empty() { " " } else { before }
            ),
        }
    })
}

impl Edit {
    fn span(&self) -> (usize, usize) {
        match *self {
            Edit::Vary { at, len } => (at, len),
            Edit::Open { at, .. } => (at, 0),
        }
    }
}

fn edits_ascend_one_per_unit(units: &[(usize, usize)], edits: &[Edit]) -> bool {
    let ascend = edits.windows(2).all(|w| w[0].span().0 <= w[1].span().0);
    let varied_units: Vec<Option<usize>> = edits
        .iter()
        .filter_map(|edit| match *edit {
            Edit::Vary { at, .. } => Some(
                units
                    .iter()
                    .position(|&(start, width)| start <= at && at < start + width),
            ),
            Edit::Open { .. } => None,
        })
        .collect();
    ascend && varied_units.windows(2).all(|w| w[0] < w[1])
}

fn apply_edits(template: &mut String, edits: &[Edit]) {
    for edit in edits.iter().rev() {
        match edit {
            Edit::Vary { at, len } => template.replace_range(*at..at + len, VARIES_MARK),
            Edit::Open {
                at,
                unit_with_separator,
            } => template.insert_str(*at, unit_with_separator),
        }
    }
}

fn letters(w: &str) -> impl Iterator<Item = u8> + '_ {
    w.bytes().filter(u8::is_ascii_alphabetic)
}

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

fn data_shaped(w: &str) -> bool {
    let w = w
        .trim_start_matches(['+', '-'])
        .trim_end_matches(['.', ',', ';', ':', '!', '?']);
    let Some(v) = field_value(w) else {
        return true;
    };
    let bracketed =
        (v.starts_with('[') && v.ends_with(']')) || (v.starts_with('(') && v.ends_with(')'));
    bracketed
        || (v.len() >= 2 && v.starts_with('"') && v.ends_with('"'))
        || v.bytes()
            .any(|b| matches!(b, b'/' | b'.' | b'*' | b'<' | b'>' | b'\\' | b'@' | b'='))
}

fn word_unit_spans(s: &str) -> Vec<(usize, usize)> {
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
    split_units_at(s, units, &ranges, &boundaries)
}

fn split_units_at(
    s: &str,
    units: Vec<(usize, usize)>,
    ranges: &[std::ops::Range<usize>],
    boundaries: &[usize],
) -> Vec<(usize, usize)> {
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
            boundaries.dedup();
            let ranges: Vec<_> = requests
                .iter()
                .map(|(request, _)| request.range())
                .collect();
            units = split_units_at(s, units, &ranges, &boundaries);
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

struct VariesSlots<'t> {
    words: Vec<&'t str>,
    slots: Vec<(usize, usize, usize)>,
}

impl<'t> VariesSlots<'t> {
    fn new(template: &'t str, units: &[(usize, usize)]) -> Self {
        let words: Vec<&str> = units
            .iter()
            .map(|&(at, len)| &template[at..at + len])
            .collect();
        let slots = words
            .iter()
            .enumerate()
            .filter_map(|(i, w)| {
                w.find(VARIES_MARK)
                    .map(|k| (i, k, w.len() - k - VARIES_MARK.len()))
            })
            .collect();
        Self { words, slots }
    }
}

fn quoted_value(w: &str) -> Option<(&str, &str)> {
    let opened = w.trim_start_matches(['(', '[', '{']);
    let core = opened.trim_end_matches([')', ']', '}', ',', ';']);
    let inner = if core.len() >= 4 && core.starts_with("\\\"") && core.ends_with("\\\"") {
        &core[2..core.len() - 2]
    } else if core.len() >= 2 && core.starts_with('"') && core.ends_with('"') {
        &core[1..core.len() - 1]
    } else {
        return None;
    };
    if inner.contains('"') {
        return None;
    }
    let at = w.len() - opened.len();
    Some((&w[..at], &w[at + core.len()..]))
}

fn first_difference_may_vary(template: &str, line: &str) -> bool {
    let mut quotes = 0usize;
    let mut words = template.split_ascii_whitespace();
    for m in line.split_ascii_whitespace() {
        let Some(t) = words.next() else {
            return true;
        };
        if t != m {
            return t.contains('"') || t.contains(VARIES_MARK) || quotes % 2 == 1;
        }
        quotes += t.bytes().filter(|&b| b == b'"').count();
    }
    true
}

enum SlotReading {
    Same,
    QuotedValueInsideSlot,
    OtherQuotedValue,
}

fn read_through_slots(template_unit: &str, line_unit: &str) -> Option<SlotReading> {
    if template_unit == line_unit {
        return Some(SlotReading::Same);
    }
    let around = quoted_value(line_unit)?;
    match slot_affix(template_unit) {
        Some(kept) => (around == kept).then_some(SlotReading::QuotedValueInsideSlot),
        None => {
            (quoted_value(template_unit) == Some(around)).then_some(SlotReading::OtherQuotedValue)
        }
    }
}

fn joins_through_slots(
    template: &str,
    template_units: &[(usize, usize)],
    line: &str,
    line_units: &[(usize, usize)],
    threshold: u8,
) -> bool {
    if template_units.len() != line_units.len() || template_units.is_empty() {
        return false;
    }
    let mut diffs = 0usize;
    for (&(ta, tl), &(la, ll)) in template_units.iter().zip(line_units) {
        match read_through_slots(&template[ta..ta + tl], &line[la..la + ll]) {
            None => return false,
            Some(SlotReading::OtherQuotedValue) => diffs += 1,
            Some(SlotReading::Same | SlotReading::QuotedValueInsideSlot) => {}
        }
    }
    let n = template_units.len();
    let agree = (n - diffs) as f64 / n as f64 * 100.0;
    agree >= f64::from(threshold)
}

pub(super) fn plain_word_diffs(a: &str, b: &str) -> Option<usize> {
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
    if !alignable(ua.len(), ub.len()) {
        return None;
    }
    let aligned = align_words(&ua, &ub);
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
    Some(
        diffs
            + ub.iter()
                .zip(&matched_b)
                .filter(|(u, m)| !**m && lone_unit(u, &ua))
                .count(),
    )
}

fn within_plain_word_allowance(a: &str, b: &str) -> bool {
    plain_word_diffs(a, b).is_some_and(|diffs| diffs <= MAX_PLAIN_WORD_DIFFS)
}

fn seed_for_group(normalized: &str) -> u64 {
    fnv1a(normalized.as_bytes())
}

#[cfg(test)]
fn render_compact_marker(
    count: usize,
    rollup: &GroupRollup,
    first_ts: Option<&str>,
    last_ts: Option<&str>,
    inline_threshold: usize,
) -> String {
    render_compact_marker_with(count, rollup, first_ts, last_ts, None, inline_threshold)
}

fn render_compact_marker_with(
    count: usize,
    rollup: &GroupRollup,
    first_ts: Option<&str>,
    last_ts: Option<&str>,
    bunched: Option<&str>,
    inline_threshold: usize,
) -> String {
    let mut out = format!("[+{count} similar");

    if let (Some(a), Some(b)) = (first_ts, last_ts) {
        out.push_str(" | ");
        out.push_str(a);
        out.push_str(" → ");
        out.push_str(b);
        if let Some(clause) = bunched {
            out.push_str(" | ");
            out.push_str(clause);
        }
    }

    let worthy: Vec<(&&'static str, &VariationEntry)> = rollup
        .iter()
        .filter(|(_, entry)| !entry.samples.is_empty() || entry.distinct_count <= inline_threshold)
        .filter(|(_, entry)| entry.distinct_count > 0)
        .collect();

    if !worthy.is_empty() {
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

        fn push_entry(
            out: &mut String,
            name: &str,
            entry: &VariationEntry,
            inline_threshold: usize,
        ) {
            out.push_str(name);
            out.push('×');
            out.push_str(&entry.distinct_count.to_string());
            if entry.capped {
                out.push('+');
            }
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

        out.push_str(" | ");
        let mut first = true;
        for (name, entry) in &worthy {
            if !first {
                out.push_str(", ");
            }
            first = false;
            let name = name.to_lowercase();
            match &entry.slots {
                Some(slots) => {
                    for (i, slot) in slots.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        push_entry(&mut out, &name, slot, inline_threshold);
                    }
                }
                None => push_entry(&mut out, &name, entry, inline_threshold),
            }
        }
    }

    out.push(']');
    out
}

#[derive(Debug)]
enum Accumulator {
    Values(HashSet<String>),
    Hashes(HashSet<u64>),
}

impl Accumulator {
    fn len(&self) -> usize {
        match self {
            Self::Values(s) => s.len(),
            Self::Hashes(s) => s.len(),
        }
    }

    fn empty_like(other: &Self) -> Self {
        match other {
            Self::Values(_) => Self::Values(HashSet::new()),
            Self::Hashes(_) => Self::Hashes(HashSet::new()),
        }
    }

    fn merge_sorted(&mut self, other: Self, cap: usize) -> bool {
        debug_assert_eq!(
            std::mem::discriminant(self),
            std::mem::discriminant(&other),
            "a token type keeps its values the same way in every group"
        );
        match (self, other) {
            (Self::Values(into), Self::Values(from)) => merge_sorted_within_cap(into, from, cap),
            (Self::Hashes(into), Self::Hashes(from)) => merge_sorted_within_cap(into, from, cap),
            _ => false,
        }
    }
}

fn insert_within_cap<T: Eq + std::hash::Hash>(set: &mut HashSet<T>, value: T, cap: usize) -> bool {
    if set.len() >= cap && !set.contains(&value) {
        return false;
    }
    set.insert(value);
    true
}

fn merge_sorted_within_cap<T: Ord + std::hash::Hash>(
    into: &mut HashSet<T>,
    from: HashSet<T>,
    cap: usize,
) -> bool {
    let mut from: Vec<T> = from.into_iter().collect();
    from.sort_unstable();
    for value in from {
        if into.contains(&value) {
            continue;
        }
        if into.len() >= cap {
            return true;
        }
        into.insert(value);
    }
    false
}

struct RollupComputer {
    k: usize,
    distinct_cap: usize,
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

    fn accumulate_tokens(&self, lines: &[LogLine], per_type: &mut PerType) {
        let capacity_hint = lines.len().min(self.distinct_cap);

        for line in lines {
            let secrets = self
                .sanitizer
                .as_ref()
                .and_then(|z| z.line_secrets(&line.original));
            for token in &line.tokens {
                let name = token_type_name(token);
                let sample_worthy = is_sample_worthy(token);

                let entry = per_type.entry(name).or_insert_with(|| TypeValues {
                    values: if sample_worthy {
                        Accumulator::Values(HashSet::with_capacity(capacity_hint))
                    } else {
                        Accumulator::Hashes(HashSet::with_capacity(capacity_hint))
                    },
                    capped: false,
                });

                if entry.capped {
                    continue;
                }

                let kept = match &mut entry.values {
                    Accumulator::Values(s) => {
                        let mut v = token_value_string(token);
                        if let Some(masked) = secrets.as_ref().and_then(|x| x.mask(&v)) {
                            v = masked;
                        }
                        insert_within_cap(s, v, self.distinct_cap)
                    }
                    Accumulator::Hashes(s) => {
                        insert_within_cap(s, hash_token_value(token), self.distinct_cap)
                    }
                };
                entry.capped = !kept;
            }
        }
    }

    fn accumulate_varies(&self, lines: &[LogLine], template: &str, varies: &mut SlotCounts) {
        self.accumulate_varies_counted(
            lines.iter().map(|line| (line.normalized.as_str(), 1)),
            template,
            varies,
        );
    }

    fn accumulate_varies_counted<'a>(
        &self,
        lines: impl Iterator<Item = (&'a str, usize)>,
        template: &str,
        varies: &mut SlotCounts,
    ) {
        let template = VariesSlots::new(template, &unit_spans(template));
        if template.slots.is_empty() {
            return;
        }
        for (normalized, count) in lines {
            let units = unit_spans(normalized);
            self.accumulate_member_varies(&template, normalized, &units, count, varies);
        }
    }

    fn accumulate_member_varies(
        &self,
        template: &VariesSlots<'_>,
        normalized: &str,
        units: &[(usize, usize)],
        count: usize,
        varies: &mut SlotCounts,
    ) {
        let tmpl_words = &template.words;
        let member: Vec<&str> = units
            .iter()
            .map(|&(at, len)| &normalized[at..at + len])
            .collect();
        let aligned = align_words(tmpl_words, &member);
        let mut ranges = None;
        for (s, &(i, k, q)) in template.slots.iter().enumerate() {
            let masked;
            let range = match aligned[i] {
                Some(j) => Some((j, j + 1)),
                None => ranges
                    .get_or_insert_with(|| unit_ranges(tmpl_words, &member, &aligned).stands_for)
                    [i],
            };
            let value = match range.filter(|&(from, to)| from < to) {
                Some(range) => {
                    let w = range_text(normalized, units, range);
                    let w = if let Some(z) = &self.sanitizer {
                        masked = z.mask_text(w);
                        masked.as_str()
                    } else {
                        w
                    };
                    let prefix = &tmpl_words[i][..k];
                    let suffix = &tmpl_words[i][tmpl_words[i].len() - q..];
                    w.strip_prefix(prefix)
                        .and_then(|v| v.strip_suffix(suffix))
                        .unwrap_or(w)
                }
                None => ABSENT,
            };
            slot_mut(varies, s).add(value, count, self.distinct_cap);
        }
    }

    fn accumulate_retained_varies(
        &self,
        line: &LogLine,
        line_units: &[(usize, usize)],
        template: &VariesSlots<'_>,
        state: &mut RetainedState,
    ) {
        if line_units.len() == template.words.len() {
            state.positional_members += 1;
            if !template.slots.is_empty() {
                self.accumulate_member_varies(
                    template,
                    &line.normalized,
                    line_units,
                    1,
                    &mut state.varies,
                );
            }
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

    fn accumulate_new_varies(
        &self,
        template: &str,
        units: &[(usize, usize)],
        edits: &[Edit],
        state: &mut RetainedState,
    ) {
        debug_assert!(
            edits_ascend_one_per_unit(units, edits),
            "a slot's index counts the slots made before it, so edits must ascend, \
             at most one inside each template unit: {edits:?}"
        );
        let mut made = 0;
        for edit in edits {
            let (at, len) = edit.span();
            if template[at..at + len].contains(VARIES_MARK) {
                state.slot_widened_after_counting = true;
                continue;
            }
            let index = made
                + units
                    .iter()
                    .take_while(|&&(s, w)| s + w <= at)
                    .filter(|&&(s, w)| template[s..s + w].contains(VARIES_MARK))
                    .count();
            state
                .varies
                .resize_with(state.varies.len().max(index), VariesCounts::default);
            state.varies.insert(index, VariesCounts::default());
            made += 1;
            if state.positional_members == 0 {
                continue;
            }
            let value = if len == 0 {
                ABSENT.to_string()
            } else {
                let &(start, width) = units
                    .iter()
                    .find(|&&(start, width)| start <= at && at + len <= start + width)
                    .expect("a varying edit is inside one template unit");
                let unit = &template[start..start + width];
                let masked = match &self.sanitizer {
                    Some(z) => z.mask_text(unit),
                    None => unit.to_string(),
                };
                masked
                    .strip_prefix(&template[start..at])
                    .and_then(|v| v.strip_suffix(&template[at + len..start + width]))
                    .unwrap_or(&masked)
                    .to_string()
            };
            state.varies[index].add(&value, state.positional_members, self.distinct_cap);
        }
    }

    fn compute(&self, group: &PatternGroup) -> GroupRollup {
        let mut per_type = PerType::new();
        self.accumulate_tokens(&group.lines, &mut per_type);
        let mut varies = SlotCounts::new();
        self.accumulate_varies(&group.lines, group.template(), &mut varies);
        self.finalize(
            per_type,
            varies,
            group.template(),
            &group.first().normalized,
        )
    }

    fn seed(&self, group: &PatternGroup) -> RetainedState {
        let mut state = RetainedState::default();
        self.accumulate_tokens(&group.lines, &mut state.per_type);
        let template = VariesSlots::new(group.template(), &unit_spans(group.template()));
        for line in &group.lines {
            let line_units = unit_spans(&line.normalized);
            self.accumulate_retained_varies(line, &line_units, &template, &mut state);
        }
        state
    }

    fn finalize_retained(
        &self,
        mut state: RetainedState,
        template: &str,
        seed_key: &str,
    ) -> GroupRollup {
        if !state.varies_counts_known() {
            state.varies = (0..slot_count(template))
                .map(|_| VariesCounts {
                    capped: true,
                    ..VariesCounts::default()
                })
                .collect();
        } else {
            self.accumulate_varies_counted(
                state.realign.iter().map(|(text, &n)| (text.as_str(), n)),
                template,
                &mut state.varies,
            );
        }
        self.finalize(state.per_type, state.varies, template, seed_key)
    }

    fn merge_retained(&self, into: &mut RetainedState, from: RetainedState) {
        into.positional_members += from.positional_members;
        into.realign_capped |= from.realign_capped;
        into.slot_widened_after_counting |= from.slot_widened_after_counting;
        for (form, n) in from.realign {
            self.retain_realign_form(into, &form, n);
        }
        for (name, from_type) in from.per_type {
            let entry = into.per_type.entry(name).or_insert_with(|| TypeValues {
                values: Accumulator::empty_like(&from_type.values),
                capped: false,
            });
            entry.capped |= from_type.capped;
            if entry
                .values
                .merge_sorted(from_type.values, self.distinct_cap)
            {
                entry.capped = true;
            }
        }
        for (i, slot) in from.varies.into_iter().enumerate() {
            let into = slot_mut(&mut into.varies, i);
            for (value, n) in slot.counts {
                into.add(&value, n, self.distinct_cap);
            }
            into.capped |= slot.capped;
        }
    }

    fn finalize(
        &self,
        per_type: PerType,
        varies: SlotCounts,
        template: &str,
        seed_key: &str,
    ) -> GroupRollup {
        let mut rng = ChaCha8Rng::seed_from_u64(seed_for_group(seed_key));
        let mut out: GroupRollup = BTreeMap::new();
        for (name, TypeValues { values, capped }) in per_type {
            let distinct_count = values.len();
            let samples = match values {
                Accumulator::Values(s) => {
                    let mut distinct: Vec<String> = s.into_iter().collect();
                    distinct.sort();
                    let drawn_refs: Vec<&String> =
                        distinct.choose_multiple(&mut rng, self.k).collect();
                    let mut drawn: Vec<String> = drawn_refs.into_iter().cloned().collect();
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
                    counts: None,
                    slots: None,
                },
            );
        }
        if template.contains(VARIES_MARK) {
            let mut slots = varies;
            slots.resize_with(slot_count(template).max(1), VariesCounts::default);
            let entry = if slots.len() == 1 {
                let only = slots.pop().expect("one slot");
                self.varies_entry(only.counts, only.capped)
            } else {
                let mut pooled = VariesCounts::default();
                let mut capped = false;
                for slot in &slots {
                    capped |= slot.capped;
                    for (value, &n) in &slot.counts {
                        pooled.add(value, n, self.distinct_cap);
                    }
                }
                let mut entry = self.varies_entry(pooled.counts, capped || pooled.capped);
                entry.slots = Some(
                    slots
                        .into_iter()
                        .map(|slot| self.varies_entry(slot.counts, slot.capped))
                        .collect(),
                );
                entry
            };
            out.insert(VARIES, entry);
        }
        out
    }
}

impl RollupComputer {
    fn varies_entry(&self, counts: HashMap<String, usize>, capped: bool) -> VariationEntry {
        let distinct_count = counts.len();
        let mut by_count: Vec<(String, usize)> = counts.into_iter().collect();
        by_count.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if by_count.len() > self.k {
            let rarest = by_count.pop().expect("more than k");
            by_count.truncate(self.k - 1);
            by_count.push(rarest);
        }
        let (samples, counts) = by_count.into_iter().unzip();
        VariationEntry {
            distinct_count,
            samples,
            capped,
            counts: Some(counts),
            slots: None,
        }
    }
}

fn slot_count(template: &str) -> usize {
    unit_spans(template)
        .iter()
        .filter(|&&(at, len)| template[at..at + len].contains(VARIES_MARK))
        .count()
}

type MemberIndexes = std::collections::BTreeSet<usize>;

fn members_that_moved_the_template(group: &PatternGroup) -> MemberIndexes {
    let mut chosen = MemberIndexes::new();
    let mut template = group.lines[0].normalized.clone();
    chosen.insert(0);
    for (idx, line) in group.lines.iter().enumerate().skip(1) {
        if line.hash == group.lines[0].hash {
            continue;
        }
        let edits = template_edits(&template, &line.normalized).unwrap_or_default();
        if edits.is_empty() {
            continue;
        }
        apply_edits(&mut template, &edits);
        chosen.insert(idx);
    }
    chosen
}

struct DistinctForms {
    count: usize,
    past_the_kept_forms: Vec<usize>,
}

fn one_member_per_form(group: &PatternGroup, chosen: &mut MemberIndexes) -> DistinctForms {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut past_the_kept_forms: Vec<usize> = Vec::new();
    for (idx, line) in group.lines.iter().enumerate() {
        if !seen.insert(line.hash) {
            continue;
        }
        if seen.len() <= DISTILL_FORMS {
            chosen.insert(idx);
        } else if seen.len() <= ROLLUP_DISTINCT_CAP + 1 {
            past_the_kept_forms.push(idx);
        } else {
            break;
        }
    }
    DistinctForms {
        count: seen.len(),
        past_the_kept_forms,
    }
}

fn keep_members_with_unseen_token_types(group: &PatternGroup, chosen: &mut MemberIndexes) {
    let mut types_seen: std::collections::BTreeSet<&'static str> = chosen
        .iter()
        .flat_map(|&i| group.lines[i].tokens.iter().map(token_type_name))
        .collect();
    for (idx, line) in group.lines.iter().enumerate() {
        if line
            .tokens
            .iter()
            .any(|t| !types_seen.contains(token_type_name(t)))
        {
            types_seen.extend(line.tokens.iter().map(token_type_name));
            chosen.insert(idx);
        }
    }
}

fn keep_earliest_members_until(held: usize, members: usize, chosen: &mut MemberIndexes) {
    for idx in 0..held {
        if chosen.len() >= members {
            break;
        }
        chosen.insert(idx);
    }
}

struct SummaryRows {
    display: Vec<(usize, String)>,
    total_patterns: usize,
    was_capped: bool,
    fit_truncated: usize,
}

pub struct TopGroups {
    pub shown: Vec<(usize, String)>,
    pub total_groups: usize,
    pub coverage_pct: usize,
    pub fit_truncated: usize,
}

impl PatternFolder {
    pub fn new(config: Config) -> Self {
        let sanitizer = config.sanitizer();
        let normalizer = Normalizer::new(config.clone());
        let detection = match config.thread_count {
            Some(1) => LineDetection::Inline,
            Some(requested) if requested > 1 => {
                let cores = std::thread::available_parallelism().map_or(8, usize::from);
                let n = requested.min(cores);
                if n < requested {
                    eprintln!(
                        "lessence: capping --threads {requested} at {n} (available parallelism)"
                    );
                }
                match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
                    Ok(pool) => LineDetection::SizedPool(pool),
                    Err(e) => {
                        eprintln!(
                            "lessence: could not create a {n}-thread pool ({e}); \
                             falling back to the default thread pool"
                        );
                        LineDetection::GlobalPool
                    }
                }
            }
            _ => LineDetection::GlobalPool,
        };

        Self {
            config,
            normalizer,
            detection,
            buffer: Vec::new(),
            group_index: ahash::AHashMap::new(),
            stats: FoldingStats::default(),
            position_counter: 0,
            batch_buffer: Vec::new(),
            batch_locations: Vec::new(),
            sources: Vec::new(),
            markdown_entries: Vec::new(),
            next_json_id: 0,
            input_facts: InputFacts::default(),
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
            distill_groups: Vec::new(),
            retained: ahash::AHashMap::new(),
            retained_index: retained_index::RetainedIndex::default(),
            json_retention_cap_hits: 0,
        }
    }

    pub(crate) fn take_distilled(&mut self) -> Vec<DistillGroup> {
        std::mem::take(&mut self.distill_groups)
    }

    pub fn absorb_ingest_report(&mut self, report: &IngestReport, failed_sources: usize) {
        self.record_ingest_metadata(report, failed_sources);
        self.stats.total_lines += report.continuation_lines_absorbed;
        self.stats.continuation_lines_absorbed += report.continuation_lines_absorbed;
        self.stats.lines_saved += report.continuation_lines_absorbed;
    }

    pub fn record_ingest_metadata(&mut self, report: &IngestReport, failed_sources: usize) {
        self.input_facts.absorb(report, failed_sources);
    }

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

    fn is_json_output(&self) -> bool {
        matches!(self.config.output_format.as_str(), "json" | "jsonl")
    }

    fn is_markdown_output(&self) -> bool {
        self.config.output_format.as_str() == "markdown"
    }

    pub fn process_line(&mut self, line: &str) -> Result<Option<String>> {
        self.process_line_impl(line, None)
    }

    pub fn process_line_at(
        &mut self,
        line: &str,
        source_id: Option<SourceId>,
        line_no: usize,
    ) -> Result<Option<String>> {
        let location = LineLocation::new(source_id.unwrap_or(SourceId::STDIN), line_no);
        self.process_line_impl(line, Some(location))
    }

    fn process_line_impl(
        &mut self,
        line: &str,
        location: Option<LineLocation>,
    ) -> Result<Option<String>> {
        self.stats.total_lines += 1;
        if matches!(self.detection, LineDetection::Inline) {
            let normalized_line = self.normalizer.normalize_line(line.to_string())?;
            return self.place_line(normalized_line, location);
        }
        self.batch_buffer.push(line.to_string());
        if let Some(location) = location {
            self.batch_locations.push(location);
        }
        if self.batch_buffer.len() >= BATCH_LINES {
            self.process_batch()?;
        }
        Ok(None)
    }

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
            first_diff: first_diff(line, nearest.first(), self.sanitizer.as_ref()),
        })
    }

    #[cfg(test)]
    fn cluster_line_at(&mut self, normalized_line: LogLine, location: Option<LineLocation>) {
        self.cluster_line_timed(normalized_line, location, None);
    }

    fn cluster_line_timed(
        &mut self,
        normalized_line: LogLine,
        location: Option<LineLocation>,
        epoch: Option<i64>,
    ) {
        if let Some(group) = self.retained.get_mut(&normalized_line.hash) {
            let loc = location
                .unwrap_or_else(|| LineLocation::new(SourceId::STDIN, self.position_counter));
            if let Some(epoch) = epoch {
                group.timeline.record(epoch);
            }
            group.retained_rejoin(
                normalized_line,
                loc,
                &[],
                &self.rollup_computer,
                self.config.min_collapse,
            );
            return;
        }
        let mut edits = Vec::new();
        let match_index = if let Some(&idx) = self.group_index.get(&normalized_line.hash) {
            Some(idx)
        } else {
            let retained_match = if self.retained.is_empty() {
                None
            } else {
                self.retained_index
                    .candidates(&normalized_line, self.config.threshold)
                    .into_iter()
                    .filter_map(|key| {
                        let group = self.retained.get(&key)?;
                        if !(self.normalizer.are_similar(&normalized_line, group.first())
                            && within_plain_word_allowance(
                                &normalized_line.normalized,
                                &group.first().normalized,
                            ))
                        {
                            return None;
                        }
                        Some((group.position, key, group.edits_for(&normalized_line)?))
                    })
                    .min_by_key(|&(position, _, _)| position)
            };
            let before = retained_match
                .as_ref()
                .map_or(usize::MAX, |&(position, _, _)| position);
            let mut line_units: Option<Vec<(usize, usize)>> = None;
            let threshold = self.config.threshold;
            let live_match = self
                .buffer
                .iter()
                .take_while(|g| g.position < before)
                .position(|group| {
                    let first = group.first();
                    let similar = self.normalizer.are_similar(&normalized_line, first)
                        || (group.slot_units.is_some()
                            && group.joins_through_slots(
                                &normalized_line,
                                &mut line_units,
                                threshold,
                            ));
                    similar
                        && within_plain_word_allowance(
                            &normalized_line.normalized,
                            &first.normalized,
                        )
                        && group
                            .edits_for(&normalized_line)
                            .map(|found| edits = found)
                            .is_some()
                });
            if live_match.is_none()
                && let Some((_, key, edits)) = retained_match
            {
                let loc = location
                    .unwrap_or_else(|| LineLocation::new(SourceId::STDIN, self.position_counter));
                let group = self.retained.get_mut(&key).expect("indexed retained group");
                if let Some(epoch) = epoch {
                    group.timeline.record(epoch);
                }
                group.retained_rejoin(
                    normalized_line,
                    loc,
                    &edits,
                    &self.rollup_computer,
                    self.config.min_collapse,
                );
                return;
            }
            live_match
        };

        let distill_line_no = self
            .config
            .distill
            .is_some()
            .then(|| location.map_or(self.position_counter, |l| l.line_no));

        if let Some(index) = match_index {
            if let Some(epoch) = epoch {
                self.buffer[index].timeline.record(epoch);
            }
            let location = location
                .unwrap_or_else(|| LineLocation::new(SourceId::STDIN, self.position_counter));
            self.buffer[index].add_line_at(normalized_line, location, &edits);
            if let Some(line_no) = distill_line_no {
                self.buffer[index].member_line_nos.push(line_no);
            }
        } else {
            let nearest = self
                .config
                .explain
                .then(|| self.nearest_group(&normalized_line))
                .flatten();

            let rep_hash = normalized_line.hash;
            let mut group = if let Some(location) = location {
                PatternGroup::new_at(normalized_line, self.position_counter, location)
            } else {
                PatternGroup::new(normalized_line, self.position_counter)
            };
            group.nearest = nearest;
            if let Some(epoch) = epoch {
                group.timeline.record(epoch);
            }
            if let Some(line_no) = distill_line_no {
                group.member_line_nos.push(line_no);
            }
            self.buffer.push(group);
            let prev = self.group_index.insert(rep_hash, self.buffer.len() - 1);
            debug_assert!(prev.is_none(), "duplicate representative hash in buffer");
            self.assert_one_key_space(rep_hash);
        }
    }

    fn distill_take(&mut self, group: &PatternGroup, members: usize) {
        let mut all_types: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();
        for line in &group.lines {
            for t in &line.tokens {
                all_types.insert(token_type_name(t));
            }
        }
        let structure: std::collections::BTreeSet<&'static str> =
            group.first().tokens.iter().map(token_type_name).collect();

        let mut record = DistillGroup {
            template: group.template().to_string(),
            token_types: structure.into_iter().collect(),
            all_types: all_types.into_iter().collect(),
            anchor: group.first().anchor,
            avg_bytes: group.lines.iter().map(|l| l.original.len()).sum::<usize>()
                / group.lines.len().max(1),
            kept: Vec::new(),
            capping_extra: Vec::new(),
            count: group.count(),
            distinct_forms: 0,
        };

        if !group.should_collapse(self.config.min_collapse) {
            record.distinct_forms = group
                .lines
                .iter()
                .map(|l| l.hash)
                .collect::<HashSet<u64>>()
                .len();
            record.kept.clone_from(&group.member_line_nos);
            record.kept.sort_unstable();
            self.distill_groups.push(record);
            return;
        }

        let mut chosen = members_that_moved_the_template(group);
        let forms = one_member_per_form(group, &mut chosen);
        keep_members_with_unseen_token_types(group, &mut chosen);
        keep_earliest_members_until(group.lines.len(), members, &mut chosen);

        record.distinct_forms = forms.count;
        record.kept = chosen
            .iter()
            .filter_map(|i| group.member_line_nos.get(*i).copied())
            .collect();
        record.kept.sort_unstable();

        if forms.count > ROLLUP_DISTINCT_CAP && record.avg_bytes <= DISTILL_CHEAP_LINE_BYTES {
            record.capping_extra = forms
                .past_the_kept_forms
                .iter()
                .filter_map(|i| group.member_line_nos.get(*i).copied())
                .collect();
            record.capping_extra.sort_unstable();
        }

        self.distill_groups.push(record);
    }

    fn flush_oldest_safe_group(&mut self) -> Result<Option<String>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let current_position = self.position_counter;

        let mut oldest_index = None;
        let mut oldest_position = usize::MAX;

        for (i, group) in self.buffer.iter().enumerate() {
            let is_old_enough = current_position - group.position > EVICTION_DISTANCE;
            let is_ready = group.should_collapse(self.config.min_collapse) || is_old_enough;

            if is_ready && group.position < oldest_position {
                oldest_position = group.position;
                oldest_index = Some(i);
            }
        }

        if let Some(index) = oldest_index {
            let group = self.buffer.remove(index);
            self.group_index.remove(&group.first().hash);
            for v in self.group_index.values_mut() {
                if *v > index {
                    *v -= 1;
                }
            }
            let mut group = match self.retain_evicted_group(group) {
                Retention::Kept => return Ok(None),
                Retention::Declined(group) => group,
            };
            let formatted = self.format_group_dispatch(&mut group)?;
            self.stats.output_lines += formatted.lines().count();
            if self.is_markdown_output() {
                self.markdown_entries.push(formatted);
                return Ok(None);
            }
            if self.is_json_output() {
                self.json_groups_emitted += 1;
            }
            return Ok(Some(formatted));
        }

        Ok(None)
    }

    fn assert_one_key_space(&self, founding_hash: u64) {
        debug_assert!(
            !(self.group_index.contains_key(&founding_hash)
                && self.retained.contains_key(&founding_hash)),
            "a founding hash keys a live group or a retained one, never both"
        );
    }

    fn retain_evicted_group(&mut self, mut group: PatternGroup) -> Retention {
        if self.config.distill.is_some() {
            return Retention::Declined(Box::new(group));
        }
        let key = group.first().hash;
        let already_retained = self.retained.contains_key(&key);
        if !already_retained && self.retained.len() >= RETAINED_TEMPLATE_CAP {
            self.json_retention_cap_hits += 1;
            return Retention::Declined(Box::new(group));
        }
        let state = self.rollup_computer.seed(&group);
        let first = group.first().clone();
        if group.count() >= self.config.min_collapse {
            group.lines = if group.count() <= 1 {
                vec![first]
            } else {
                vec![first, group.last().clone()]
            };
        }
        group.retained = Some(state);
        group.assert_members_held();
        if !already_retained {
            self.retained_index.insert(group.first());
        }
        self.retained.insert(key, group);
        self.assert_one_key_space(key);
        Retention::Kept
    }

    fn prepare_summary(
        &mut self,
        top_n: Option<usize>,
        fit_budget: Option<usize>,
    ) -> Result<SummaryRows> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        let mut merged: HashMap<(String, u64), (usize, String)> = HashMap::new();
        for group in &self.buffer {
            let key = (group.template().to_string(), group.first().anchor);
            let count = group.count();
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

        let mut sorted: Vec<(usize, String)> = merged.into_values().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let total_patterns = sorted.len();
        use crate::config::DEFAULT_SUMMARY_CAP;

        let (limit, was_capped, fit_truncated) = match (top_n, fit_budget) {
            (Some(n), _) if n != TOP_SHOWS_EVERY_GROUP => (n, false, 0),
            (_, Some(budget)) if total_patterns > budget => {
                let show = budget.saturating_sub(1);
                (show, false, total_patterns - show)
            }
            (Some(TOP_SHOWS_EVERY_GROUP), _) | (_, Some(_)) => (total_patterns, false, 0),
            _ => (DEFAULT_SUMMARY_CAP, total_patterns > DEFAULT_SUMMARY_CAP, 0),
        };
        sorted.truncate(limit);

        Ok(SummaryRows {
            display: sorted,
            total_patterns,
            was_capped,
            fit_truncated,
        })
    }

    fn fix_timeline_grid(&mut self) {
        let span = match (&self.stats.span_first, &self.stats.span_last) {
            (Some(first), Some(last)) => crate::briefing::span_epochs(first, last),
            _ => None,
        };
        self.stats.timeline_grid = span.and_then(|(f, l)| self.stats.histogram.grid(f, l));
    }

    pub fn finish(&mut self) -> Result<Vec<String>> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }

        let mut output = Vec::new();
        self.fix_timeline_grid();

        self.group_index.clear();
        let mut groups: Vec<PatternGroup> = std::mem::take(&mut self.buffer);
        groups.extend(std::mem::take(&mut self.retained).into_values());
        self.retained_index = retained_index::RetainedIndex::default();
        groups.sort_by_key(|group| group.position);
        let groups = self.merge_converged(groups);

        for mut group in groups {
            let formatted = self.format_group_dispatch(&mut group)?;
            self.stats.output_lines += formatted.lines().count();
            if self.is_markdown_output() {
                self.markdown_entries.push(formatted);
            } else {
                output.push(formatted);
            }
        }
        if self.is_json_output() {
            self.json_groups_emitted += output.len();
        }

        Ok(output)
    }

    fn merge_converged(&self, groups: Vec<PatternGroup>) -> Vec<PatternGroup> {
        if self.config.distill.is_some() || groups.len() < 2 {
            return groups;
        }
        let mut by_claim: HashMap<(String, u64), usize> = HashMap::with_capacity(groups.len());
        let mut out: Vec<PatternGroup> = Vec::with_capacity(groups.len());
        for group in groups {
            let key = (group.template().to_string(), group.first().anchor);
            if let Some(&at) = by_claim.get(&key) {
                out[at].absorb(group, &self.rollup_computer, self.config.min_collapse);
            } else {
                by_claim.insert(key, out.len());
                out.push(group);
            }
        }
        out
    }

    pub fn finish_top_n(
        &mut self,
        n: usize,
        fit_budget: Option<usize>,
        cap_is_summary: bool,
    ) -> Result<TopGroups> {
        if !self.batch_buffer.is_empty() {
            self.process_batch()?;
        }
        debug_assert!(
            self.retained.is_empty(),
            "a ranked run never evicts, so every group is still in the live buffer"
        );
        let n = if n == TOP_SHOWS_EVERY_GROUP {
            usize::MAX
        } else {
            n
        };
        self.fix_timeline_grid();

        let previously_formatted = self.next_json_id;

        self.group_index.clear();
        let mut all_groups: Vec<PatternGroup> = std::mem::take(&mut self.buffer);
        all_groups.sort_by_key(|group| group.position);
        let all_groups = self.merge_converged(all_groups);
        let mut groups_with_counts: Vec<(usize, PatternGroup)> =
            all_groups.into_iter().map(|g| (g.count(), g)).collect();

        groups_with_counts.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.template().cmp(b.1.template()))
        });

        let total_groups = groups_with_counts.len();
        let total_input_lines = self.stats.total_lines;

        let mut top_groups: Vec<(usize, PatternGroup)> = Vec::with_capacity(n.min(total_groups));
        for (i, (count, group)) in groups_with_counts.into_iter().enumerate() {
            if i < n {
                top_groups.push((count, group));
            } else {
                let (first_epoch, last_epoch) = group_epoch_range(&group);
                self.stats.template_counts.record(
                    &Sanitizer::masked(
                        self.sanitizer.as_ref(),
                        group.template(),
                        &group.first().tokens,
                    ),
                    group.count(),
                    first_epoch,
                    last_epoch,
                );
            }
        }

        let mut output = Vec::new();
        for (count, mut group) in top_groups {
            let formatted = self.format_group_dispatch(&mut group)?;
            self.stats.output_lines += formatted.lines().count();
            output.push((count, formatted));
        }

        let fit_truncated = match fit_budget {
            Some(budget) if output.len() > budget => {
                let show = budget.saturating_sub(1);
                let truncated = output.len() - show;
                output.truncate(show);
                truncated
            }
            _ => 0,
        };
        let lines_covered: usize = output.iter().map(|(c, _)| c).sum();

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

        Ok(TopGroups {
            shown: output,
            total_groups,
            coverage_pct: if total_input_lines > 0 {
                (lines_covered as f64 / total_input_lines as f64 * 100.0) as usize
            } else {
                0
            },
            fit_truncated,
        })
    }

    fn should_flush_buffer(&self) -> bool {
        self.evicts_to_bound_memory() && self.buffer.len() > LIVE_GROUP_LIMIT
    }

    fn evicts_to_bound_memory(&self) -> bool {
        matches!(self.detection, LineDetection::Inline) && !self.reads_every_group_after_the_run()
    }

    fn reads_every_group_after_the_run(&self) -> bool {
        self.config.summary || self.config.top_n.is_some() || self.config.explain
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

    fn process_batch(&mut self) -> Result<()> {
        let batch = std::mem::take(&mut self.batch_buffer);
        let locations = std::mem::take(&mut self.batch_locations);
        debug_assert!(locations.is_empty() || locations.len() == batch.len());
        let processed_lines = self.parallel_pattern_detection(&batch)?;
        for (index, processed_line) in processed_lines.into_iter().enumerate() {
            let evicted = self.place_line(processed_line, locations.get(index).copied())?;
            debug_assert!(evicted.is_none(), "only the inline path evicts");
        }
        Ok(())
    }

    fn parallel_pattern_detection(&self, lines: &[String]) -> Result<Vec<LogLine>> {
        use rayon::prelude::*;

        let detect = || {
            lines
                .par_iter()
                .map(|line| self.normalizer.normalize_line(line.clone()))
                .collect::<Result<Vec<_>, _>>()
        };
        let processed_lines: Vec<LogLine> = match &self.detection {
            LineDetection::SizedPool(pool) => pool.install(detect)?,
            LineDetection::GlobalPool => detect()?,
            LineDetection::Inline => lines
                .iter()
                .map(|line| self.normalizer.normalize_line(line.clone()))
                .collect::<Result<Vec<_>, _>>()?,
        };

        Ok(processed_lines)
    }

    #[cfg(test)]
    fn sequential_clustering(&mut self, normalized_line: LogLine) -> Result<()> {
        self.place_line(normalized_line, None).map(drop)
    }

    fn place_line(
        &mut self,
        normalized_line: LogLine,
        location: Option<LineLocation>,
    ) -> Result<Option<String>> {
        self.position_counter += 1;
        if !normalized_line.tokens.is_empty() {
            self.stats.patterns_detected += 1;
            self.count_pattern_types(&normalized_line.tokens);
        }
        self.stats
            .record_briefing_line(&normalized_line.tokens, &normalized_line.original);
        let epoch = self.stats.record_span(&normalized_line.tokens);

        self.cluster_line_timed(normalized_line, location, epoch);

        if self.should_flush_buffer() {
            return self.flush_oldest_safe_group();
        }
        Ok(None)
    }

    pub fn get_stats(&self) -> &FoldingStats {
        &self.stats
    }

    pub fn input_degraded_codes(&self) -> Vec<&'static str> {
        self.input_facts.degraded_codes()
    }
}

mod render;
mod retained_index;
mod timeline;

#[cfg(test)]
mod tests;
