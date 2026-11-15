use super::{
    BTreeMap, Completeness, Count, Duration, GroupCompleteness, GroupRecord, GroupRollup,
    IngestReport, LineRef, LogLine, PatternFolder, PatternGroup, ROLLUP_TEXT_SAMPLE_THRESHOLD,
    Result, StatsJson, SummaryRecord, TimeRange, Token, VariationCompleteness, Write,
    first_timestamp_in, group_epoch_range, io, render_compact_marker_with, token_type_name,
};
use crate::config::{GroupSink, LINES_A_COLLAPSED_GROUP_SHOWS};
use crate::run_metadata::RunMetadata;
use crate::sanitize::Sanitizer;
use serde::Serialize;

const LINES_AN_ESSENCE_GROUP_SHOWS: usize = 1;
const SUMMARY_ELLIPSIS: &str = "...";
const SUMMARY_MIN_WIDTH_WORTH_TRUNCATING_TO: usize = 20;
const FRAGMENTED_BY_RETENTION_CAP_IS_ZERO_SINCE_RETENTION_WAS_REMOVED_AND_STAYS_FOR_SCHEMA_STABILITY:
    usize = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(super) struct Masked(String);

impl Masked {
    pub(super) fn line(sanitizer: Option<&Sanitizer>, line: &str, tokens: &[Token]) -> Self {
        Self(Sanitizer::masked(sanitizer, line, tokens))
    }

    fn essence_text(sanitizer: Option<&Sanitizer>, normalized: &str) -> Self {
        Self(sanitizer.map_or_else(|| normalized.to_string(), |z| z.mask_text(normalized)))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn into_string(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub(super) struct MaskedRollup(GroupRollup);

impl MaskedRollup {
    fn new(mut rollup: GroupRollup, sanitizer: Option<&Sanitizer>) -> Self {
        if let Some(z) = sanitizer {
            mask_rollup_pii(&mut rollup, z);
        }
        Self(rollup)
    }

    fn entries(&self) -> &GroupRollup {
        &self.0
    }
}

pub(super) struct Rendered {
    pub(super) text: String,
    pub(super) collapsed: bool,
}

pub(super) enum Dispatched {
    Shown(Rendered),
    RecordedForDistill,
}

#[cfg(test)]
impl Dispatched {
    pub(super) fn expect_shown(self) -> Rendered {
        match self {
            Self::Shown(rendered) => rendered,
            Self::RecordedForDistill => panic!("a distill run renders no group"),
        }
    }
}

pub struct MarkdownEntry {
    text: String,
    folded: bool,
}

pub struct SummaryRequest {
    pub top_n: Option<usize>,
    pub fit_budget: Option<usize>,
    pub max_width: Option<usize>,
}

impl PatternFolder {
    pub(super) fn format_group_dispatch(&mut self, group: &PatternGroup) -> Result<Dispatched> {
        let briefing_template = self.mask_shown(group.template(), &group.first().tokens);
        let (first_epoch, last_epoch) = group_epoch_range(group);
        self.stats.template_counts.record(
            briefing_template.as_str(),
            group.count(),
            first_epoch,
            last_epoch,
        );

        if let GroupSink::RecordDistillMembers { members_per_group } = self.config.group_sink {
            self.distill_take(group, members_per_group);
            return Ok(Dispatched::RecordedForDistill);
        }
        let rollup = self.rollup_unless_too_small_to_collapse(group);
        let rendered = if self.is_json_output() {
            Rendered {
                text: self.format_group_json(group, rollup)?,
                collapsed: false,
            }
        } else {
            self.format_group(group, &rollup)?
        };
        self.stats.output_lines += rendered.text.lines().count();
        Ok(Dispatched::Shown(rendered))
    }

    fn rollup_unless_too_small_to_collapse(&mut self, group: &PatternGroup) -> MaskedRollup {
        let json_record_of_several_lines = self.is_json_output() && group.count() > 1;
        let rollup =
            if group.should_collapse(self.config.min_collapse) || json_record_of_several_lines {
                self.rollup_computer.compute(group)
            } else {
                if self.is_json_output() {
                    self.json_uncomputed_variation_groups += 1;
                }
                BTreeMap::new()
            };
        self.masked_rollup(rollup)
    }

    pub(super) fn masked_rollup(&self, rollup: GroupRollup) -> MaskedRollup {
        MaskedRollup::new(rollup, self.sanitizer.as_ref())
    }

    pub(super) fn format_group_json(
        &mut self,
        group: &PatternGroup,
        variation: MaskedRollup,
    ) -> Result<String> {
        let id = self.next_json_id;
        self.next_json_id += 1;

        for entry in variation.entries().values() {
            let omitted = entry.distinct_count.saturating_sub(entry.samples.len());
            if entry.capped {
                self.json_capped_entries += 1;
            }
            if entry.capped || omitted > 0 {
                self.json_sampled_entries += 1;
            }
            self.json_omitted_values_lower_bound += omitted;
        }

        self.account_savings(group);

        let mut token_types: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();
        for t in &group.first().tokens {
            token_types.insert(token_type_name(t));
        }
        for t in &group.last().tokens {
            token_types.insert(token_type_name(t));
        }

        let record = GroupRecord {
            id,
            count: group.count(),
            token_types: token_types.into_iter().collect(),
            normalized: self.mask_shown(group.template(), &group.first().tokens),
            first: LineRef {
                source: self.source_name(group.first_source_id),
                line: self.mask_shown(&group.first().original, &group.first().tokens),
                line_no: group.first_line_no,
            },
            last: LineRef {
                source: self.source_name(group.last_source_id),
                line: self.mask_shown(&group.last().original, &group.last().tokens),
                line_no: group.last_line_no,
            },
            time_range: {
                let first_seen = first_timestamp_in(&group.first().tokens);
                let view = self.timeline_view(group, first_seen.as_deref());
                let (bucket_seconds, buckets, bunched) = match view {
                    Some(v) => (Some(v.bucket_seconds), Some(v.buckets), v.bunched),
                    None => (None, None, None),
                };
                TimeRange {
                    first_seen,
                    last_seen: first_timestamp_in(&group.last().tokens),
                    bucket_seconds,
                    buckets,
                    bunched,
                }
            },
            variation,
            nearest: group.nearest.clone(),
        };

        Ok(serde_json::to_string(&record)?)
    }

    fn timeline_view(
        &self,
        group: &PatternGroup,
        first_seen: Option<&str>,
    ) -> Option<super::timeline::TimelineView> {
        let grid = self.stats.timeline_grid.as_ref()?;
        let first_stamp_carries_year = first_seen.is_none_or(crate::briefing::carries_year);
        group.timeline.view(grid, first_stamp_carries_year)
    }

    pub(super) fn account_savings(&mut self, group: &PatternGroup) {
        self.account_count(group.count());
    }

    pub(super) fn account_count(&mut self, count: usize) {
        if self.config.essence_mode {
            self.stats.lines_saved += count.saturating_sub(LINES_AN_ESSENCE_GROUP_SHOWS);
        } else if count >= self.config.min_collapse {
            self.stats.collapsed_groups += 1;
            self.stats.lines_saved += count.saturating_sub(LINES_A_COLLAPSED_GROUP_SHOWS);
        }
    }

    pub(super) fn format_group(
        &mut self,
        group: &PatternGroup,
        rollup: &MaskedRollup,
    ) -> Result<Rendered> {
        self.account_savings(group);
        let rendered = if self.config.essence_mode {
            Rendered {
                text: self.format_essence(group),
                collapsed: false,
            }
        } else if group.should_collapse(self.config.min_collapse) {
            Rendered {
                text: self.format_collapsed(group, rollup),
                collapsed: true,
            }
        } else {
            Rendered {
                text: self.format_every_line(group),
                collapsed: false,
            }
        };
        Ok(rendered)
    }

    fn format_essence(&self, group: &PatternGroup) -> String {
        self.mask_shown(group.template(), &group.first().tokens)
            .into_string()
    }

    fn format_collapsed(&self, group: &PatternGroup, rollup: &MaskedRollup) -> String {
        let first_ts = first_timestamp_in(&group.first().tokens);
        let last_ts = first_timestamp_in(&group.last().tokens);
        let clause = self
            .timeline_view(group, first_ts.as_deref())
            .and_then(|v| v.bunched)
            .map(|b| b.clause());
        let marker = if rollup.entries().is_empty() {
            self.format_marker_for_a_group_without_rollup_entries(
                group.first(),
                group.last(),
                group.hidden_members(),
            )
        } else {
            render_compact_marker_with(
                group.hidden_members(),
                rollup.entries(),
                first_ts.as_deref(),
                last_ts.as_deref(),
                clause.as_deref(),
                ROLLUP_TEXT_SAMPLE_THRESHOLD,
            )
        };

        let mut result = self
            .mask_shown(&group.first().original, &group.first().tokens)
            .into_string();
        result.push('\n');
        result.push_str(&marker);
        if group.count() > 1 {
            result.push('\n');
            result.push_str(
                self.mask_shown(&group.last().original, &group.last().tokens)
                    .as_str(),
            );
        }
        result
    }

    fn format_every_line(&self, group: &PatternGroup) -> String {
        let mut result = String::new();
        for (i, line) in group.lines.iter().enumerate() {
            if i > 0 {
                result.push('\n');
            }
            result.push_str(self.mask_shown(&line.original, &line.tokens).as_str());
        }
        result
    }

    pub(super) fn format_summary_line(
        count: usize,
        representative: &str,
        max_width: Option<usize>,
    ) -> String {
        let prefix = format!("[{count}x] ");
        match max_width {
            Some(width) if prefix.len() + representative.len() > width => {
                let avail = width.saturating_sub(prefix.len() + SUMMARY_ELLIPSIS.len());
                if avail > SUMMARY_MIN_WIDTH_WORTH_TRUNCATING_TO {
                    let mut end = avail;
                    while !representative.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{prefix}{}{SUMMARY_ELLIPSIS}", &representative[..end])
                } else {
                    format!("{prefix}{representative}")
                }
            }
            _ => format!("{prefix}{representative}"),
        }
    }

    pub(super) fn format_coverage_message(
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

    pub fn finish_summary(
        &mut self,
        request: &SummaryRequest,
        ingest_report: &IngestReport,
        failed_sources: usize,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> Result<()> {
        let super::SummaryRows {
            display,
            total_patterns,
            was_capped,
            fit_truncated,
        } = self.prepare_summary(request.top_n, request.fit_budget)?;
        let shown_count = display.len();
        self.account_summary(&display);

        let mut write_line = |s: String| -> Result<()> {
            crate::output::write_or_exit_on_closed_pipe(out, format_args!("{s}\n"))
        };
        for (count, representative) in &display {
            write_line(Self::format_summary_line(
                *count,
                representative,
                request.max_width,
            ))?;
        }

        if fit_truncated > 0 {
            write_line(format!(
                "... {fit_truncated} more patterns (remove --fit for full output)"
            ))?;
        }

        let shown_lines: usize = display.iter().map(|(c, _)| c).sum();
        writeln!(
            err,
            "{}",
            Self::format_coverage_message(
                shown_count,
                total_patterns,
                shown_lines,
                self.records_read_before_continuations_are_counted(),
                was_capped,
            )
        )?;

        self.absorb_ingest_report(ingest_report, failed_sources);
        Ok(())
    }

    fn records_read_before_continuations_are_counted(&self) -> usize {
        debug_assert_eq!(
            self.stats.continuation_lines_absorbed, 0,
            "the summary's coverage line counts records shown against records read, so it is \
             written before the ingest report adds the continuation lines to the statistics"
        );
        self.stats.total_lines
    }

    pub(super) fn account_summary(&mut self, display: &[(usize, String)]) {
        for (count, _) in display {
            self.account_count(*count);
        }
        self.stats.output_lines += display.len();
    }

    pub fn print_summary_json(&self, writer: &mut impl io::Write, elapsed: Duration) -> Result<()> {
        let record = SummaryRecord {
            stats: self.build_stats_json(elapsed),
            metadata: RunMetadata::new(&self.input_facts, self.config.sanitize.is_some()),
            completeness: {
                let group_total = self.json_groups_total.unwrap_or(self.json_groups_emitted);
                let groups_complete = self.json_omitted_by_top == 0
                    && self.json_omitted_by_summary_cap == 0
                    && self.json_omitted_by_fit == 0;
                let variation_complete = self.json_capped_entries == 0
                    && self.json_uncomputed_variation_groups == 0
                    && self.json_omitted_values_lower_bound == 0;
                Completeness {
                    complete: self
                        .input_facts
                        .completeness(self.stats.total_lines)
                        .complete
                        && groups_complete
                        && variation_complete,
                    input: self.input_facts.completeness(self.stats.total_lines),
                    groups: GroupCompleteness {
                        complete: groups_complete,
                        emitted: self.json_groups_emitted,
                        total: Count::exact(group_total),
                        omitted_by_top: Count::exact(self.json_omitted_by_top),
                        omitted_by_summary_cap: Count::exact(self.json_omitted_by_summary_cap),
                        omitted_by_fit: Count::exact(self.json_omitted_by_fit),
                        fragmented_by_retention_cap:
                            FRAGMENTED_BY_RETENTION_CAP_IS_ZERO_SINCE_RETENTION_WAS_REMOVED_AND_STAYS_FOR_SCHEMA_STABILITY,
                    },
                    variation_values: VariationCompleteness {
                        complete: variation_complete,
                        capped_entries: self.json_capped_entries,
                        sampled_entries: self.json_sampled_entries,
                        uncomputed_groups: self.json_uncomputed_variation_groups,
                        omitted_values: if self.json_uncomputed_variation_groups > 0 {
                            Count::unknown()
                        } else if self.json_capped_entries > 0 {
                            Count::lower_bound(self.json_omitted_values_lower_bound)
                        } else {
                            Count::exact(self.json_omitted_values_lower_bound)
                        },
                    },
                }
            },
            briefing: self.build_briefing(),
        };
        serde_json::to_writer(&mut *writer, &record)?;
        writeln!(writer)?;
        Ok(())
    }

    pub(super) fn build_briefing(&self) -> crate::briefing::Briefing {
        use crate::briefing::{Briefing, FormatSniff, Levels, Span};

        let stats = &self.stats;
        let total_lines = stats.total_lines;

        let source = self.sources.first().map(|s| {
            std::path::Path::new(s)
                .file_name()
                .map_or_else(|| s.clone(), |f| f.to_string_lossy().into_owned())
        });

        let (json, logfmt, plain) = (stats.format_json, stats.format_logfmt, stats.format_plain);
        let format_total = json + logfmt + plain;
        let (dominant, dominant_count) = [("json", json), ("logfmt", logfmt), ("plain", plain)]
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .unwrap_or(("plain", 0));
        let mixed = format_total > 0 && (dominant_count as f64) < (format_total as f64) * 0.9;

        debug_assert!(
            stats.template_counts.is_truncated()
                || stats.template_counts.total_members()
                    == total_lines - stats.continuation_lines_absorbed,
            "template_counts must count every input record exactly once unless its template cap \
             was hit; a continuation line --frame-continuations folded into the record above it \
             is an input line but not a record of its own: {} != {}",
            stats.template_counts.total_members(),
            total_lines - stats.continuation_lines_absorbed
        );

        let tokens =
            crate::briefing::token_classes_by_occurrence(stats.token_classes().into_iter().map(
                |(class, bucket, occurrences)| crate::briefing::TokenClass {
                    class,
                    occurrences,
                    distinct: stats.cardinality_for(bucket),
                },
            ));

        let span_epochs = match (&stats.span_first, &stats.span_last) {
            (Some(first), Some(last)) => crate::briefing::span_epochs(first, last),
            _ => None,
        };
        let duration_seconds = match (&stats.span_first, &stats.span_last) {
            (Some(first), Some(last)) => crate::briefing::span_duration_seconds(first, last),
            _ => None,
        };
        let lines_per_second = match duration_seconds {
            Some(d) if d > 0 => Some(total_lines as f64 / d as f64),
            _ => None,
        };
        let histogram = span_epochs.and_then(|(f, l)| stats.histogram.build(f, l));

        Briefing {
            source,
            lines: total_lines,
            span: Span {
                first: stats.span_first.clone(),
                last: stats.span_last.clone(),
                duration_seconds,
                lines_per_second,
                year_inferred: crate::briefing::span_year_inferred(
                    stats.span_first.as_deref(),
                    stats.span_last.as_deref(),
                ),
            },
            format: FormatSniff {
                json,
                logfmt,
                plain,
                dominant,
                mixed,
            },
            levels: Levels {
                fatal: stats.level_fatal,
                error: stats.level_error,
                warn: stats.level_warn,
                info: stats.level_info,
                debug: stats.level_debug,
                trace: stats.level_trace,
                lines_with_level: stats.level_lines_with_level,
            },
            templates: stats.template_counts.build(total_lines),
            tokens,
            histogram,
        }
    }

    pub fn print_stats<W: Write>(&self, writer: &mut W) -> Result<()> {
        let briefing = self.build_briefing();
        write!(writer, "{}", crate::briefing::render_text(&briefing))?;
        Ok(())
    }

    pub(super) fn build_stats_json(&self, elapsed: Duration) -> StatsJson {
        let compression_ratio = self.stats.compression_ratio();

        StatsJson {
            input_lines: self.stats.total_lines,
            output_lines: self.stats.output_lines,
            compression_ratio,
            collapsed_groups: self.stats.collapsed_groups,
            lines_saved: self.stats.lines_saved,
            patterns_detected: self.stats.patterns_detected,
            elapsed_ms: elapsed.as_millis() as u64,
            pattern_hits: self.stats.pattern_hits(),
        }
    }

    pub fn print_stats_json(&self, elapsed: Duration, writer: &mut impl Write) -> Result<()> {
        let stats_json = self.build_stats_json(elapsed);
        serde_json::to_writer(&mut *writer, &stats_json)?;
        writeln!(writer)?;
        Ok(())
    }
    pub fn print_preflight_json<W: Write>(&self, writer: &mut W) -> Result<()> {
        #[derive(Serialize)]
        struct Preflight {
            #[serde(flatten)]
            briefing: crate::briefing::Briefing,
            #[serde(flatten)]
            metadata: RunMetadata,
        }
        let report = Preflight {
            briefing: self.build_briefing(),
            metadata: RunMetadata::new(&self.input_facts, self.config.sanitize.is_some()),
        };
        let json = serde_json::to_string_pretty(&report)?;
        writeln!(writer, "{json}")?;
        Ok(())
    }

    pub fn emit_markdown<W: Write>(&self, entries: &[MarkdownEntry], writer: &mut W) -> Result<()> {
        let original_lines = self.stats.total_lines;
        let compressed_lines = self.stats.output_lines;
        let compression_ratio = self.stats.compression_ratio();

        let mut write_line = |s: String| -> Result<()> {
            crate::output::write_or_exit_on_closed_pipe(writer, format_args!("{s}\n"))
        };

        write_line("# Log Analysis".to_string())?;
        write_line(format!(
            "*Generated by lessence v{} on {}*\n",
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        ))?;
        write_line("## Summary\n".to_string())?;
        write_line(format!("- **Original lines**: {original_lines}"))?;
        write_line(format!("- **Compressed lines**: {compressed_lines}"))?;
        write_line(format!(
            "- **Compression ratio**: {compression_ratio:.1}%\n"
        ))?;
        write_line("## Compressed Logs\n".to_string())?;

        for (i, entry) in entries.iter().enumerate() {
            if entry.folded {
                write_line(format!("### Entry {} (Folded)\n", i + 1))?;
            }
            write_line(format!("{}\n", markdown_code_fence(&entry.text)))?;
        }
        Ok(())
    }

    pub(super) fn markdown_entry(rendered: Rendered) -> MarkdownEntry {
        MarkdownEntry {
            text: rendered.text,
            folded: rendered.collapsed,
        }
    }

    pub(super) fn format_marker_for_a_group_without_rollup_entries(
        &self,
        first: &LogLine,
        last: &LogLine,
        count: usize,
    ) -> String {
        let variation_types = self.summarize_variation_types(&first.tokens, &last.tokens);
        if variation_types.is_empty() {
            format!("[+{count} similar]")
        } else {
            format!(
                "[+{} similar, varying: {}]",
                count,
                variation_types.join(", ")
            )
        }
    }

    pub(super) fn summarize_variation_types(
        &self,
        first_tokens: &[Token],
        last_tokens: &[Token],
    ) -> Vec<String> {
        let mut types = std::collections::BTreeSet::new();

        let get_token_info = |token: &Token| -> (&'static str, String) {
            let facts = token.facts();
            let value = if facts.variation_compares_values {
                token.value_string()
            } else {
                String::new()
            };
            (facts.display_label, value)
        };

        let mut first_values: std::collections::BTreeMap<&str, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut last_values: std::collections::BTreeMap<&str, Vec<String>> =
            std::collections::BTreeMap::new();

        for token in first_tokens {
            let (token_type, value) = get_token_info(token);
            first_values.entry(token_type).or_default().push(value);
        }

        for token in last_tokens {
            let (token_type, value) = get_token_info(token);
            last_values.entry(token_type).or_default().push(value);
        }

        let all_types: std::collections::BTreeSet<&str> = first_values
            .keys()
            .chain(last_values.keys())
            .copied()
            .collect();

        for token_type in all_types {
            let first_vals = first_values.get(token_type).cloned().unwrap_or_default();
            let last_vals = last_values.get(token_type).cloned().unwrap_or_default();

            if first_vals != last_vals {
                types.insert(token_type.to_string());
            }
        }

        types.into_iter().collect()
    }

    fn mask_shown(&self, text: &str, tokens: &[Token]) -> Masked {
        if self.config.essence_mode {
            Masked::essence_text(self.sanitizer.as_ref(), text)
        } else {
            Masked::line(self.sanitizer.as_ref(), text, tokens)
        }
    }
}

fn mask_rollup_pii(rollup: &mut GroupRollup, z: &Sanitizer) {
    let entity_values = entity_values_in_rollup(rollup, z);
    mask_rollup_samples(rollup, z, &entity_values);
}

fn entity_values_in_rollup(rollup: &GroupRollup, z: &Sanitizer) -> Vec<Token> {
    let mut values: Vec<Token> = Vec::new();
    for (name, entry) in rollup {
        if z.rollup_entity(name).is_some() {
            values.extend(
                entry
                    .samples
                    .iter()
                    .filter_map(|sample| crate::sanitize::entity_token(name, sample)),
            );
        }
    }
    values
}

fn mask_rollup_samples(rollup: &mut GroupRollup, z: &Sanitizer, entity_values: &[Token]) {
    for (name, entry) in rollup.iter_mut() {
        match z.rollup_entity(name) {
            Some((crate::sanitize::Action::Redact, class)) => {
                if !entry.samples.is_empty() {
                    entry.samples = vec![format!("<{class}>")];
                }
            }
            Some((crate::sanitize::Action::KeyedPseudonym, class)) => {
                for sample in &mut entry.samples {
                    *sample = z.mask_sample(class, sample);
                }
            }
            None => {
                let slots = entry.slots.iter_mut().flatten();
                for sample in std::iter::once(&mut entry.samples)
                    .chain(slots.map(|slot| &mut slot.samples))
                    .flatten()
                {
                    *sample = z.mask_line(sample, entity_values);
                }
            }
        }
    }
}

/// Wrap untrusted log content in a CommonMark code fence so it cannot inject
/// markdown structure (headings, links, images, raw HTML) when the report is
/// rendered or ingested by an LLM/agent. The fence uses a backtick run one
/// longer than the longest run present in `content` (min 3), so embedded
/// triple-backticks can't close the fence early.
fn markdown_code_fence(content: &str) -> String {
    let mut longest_run = 0usize;
    let mut current_run = 0usize;
    for ch in content.chars() {
        if ch == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let fence = "`".repeat((longest_run + 1).max(3));
    format!("{fence}\n{content}\n{fence}")
}

#[cfg(test)]
mod fence_tests {
    use super::markdown_code_fence;

    #[test]
    fn the_fence_is_always_longer_than_any_run_in_the_content() {
        assert_eq!(
            markdown_code_fence("abc"),
            "```\nabc\n```",
            "content without backticks gets a fence of three"
        );
        let one = markdown_code_fence("a`b");
        assert!(
            one.starts_with("```\n"),
            "three is the minimum fence: {one}"
        );
        assert!(
            !one.starts_with("````"),
            "a run of one needs no longer fence than three: {one}"
        );
        let four = markdown_code_fence("````");
        assert!(
            four.starts_with("`````\n"),
            "one longer than the longest run, so the content cannot close it: {four}"
        );
        assert!(
            !four.starts_with("``````"),
            "exactly one longer, not more: {four}"
        );
        assert!(
            four.ends_with("\n`````"),
            "the closing fence matches the opening one: {four}"
        );
    }
}
