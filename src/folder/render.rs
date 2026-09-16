//! Rendering: finished fold results -> bytes, for every output mode.
//!
//! This module owns the entire "render a finished group set plus run
//! metadata" surface: the text fold output, the JSONL group and summary
//! records, the --summary lines, the markdown document, and both stats
//! reports. The folding engine in `mod.rs` produces groups as data; the
//! methods here are the only place that data becomes output. Invariants
//! held here, in one place:
//!
//! 1. PII masking (--sanitize-pii) is applied by the renderer, so every
//!    mode masks -- not just text.
//! 2. `lines_saved` / `compression_ratio` have a single definition (the
//!    text-fold arithmetic: a collapsed group preserves 3 lines), shared
//!    by the text footer, --stats-json, the JSONL summary record, and
//!    the markdown report.

use super::{
    BTreeMap, Completeness, Count, Duration, GroupCompleteness, GroupRecord, GroupRollup,
    InputCompleteness, LineRef, LogLine, PatternFolder, PatternGroup, ROLLUP_TEXT_SAMPLE_THRESHOLD,
    Result, StatsJson, SummaryRecord, TimeRange, Token, VariationCompleteness, Write,
    first_timestamp_in, group_epoch_range, io, render_compact_marker, token_type_name,
};
use crate::sanitize::Sanitizer;

impl PatternFolder {
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
    pub(super) fn format_group_dispatch(&mut self, group: &mut PatternGroup) -> Result<String> {
        // The single point every finalised group passes through, on the
        // sequential path only (the live buffer's final drain, a retained
        // group's final drain, and --top N's ranking pass all call this —
        // streaming eviction no longer does, since lessence-940: a group
        // keeps its identity past eviction instead of being formatted and
        // forgotten, so this now runs exactly once per template).
        //
        // --sanitize-pii applies here too: the briefing's top-templates
        // list is another output surface, and an unmasked template would
        // leak the exact secret/email the rest of the run redacts.
        let briefing_template = self.maybe_mask_pii(group.template(), &group.first().tokens);
        let (first_epoch, last_epoch) = group_epoch_range(group);
        self.stats.template_counts.record(
            &briefing_template,
            group.count(),
            first_epoch,
            last_epoch,
        );

        // --distill emits input lines, not rendered groups: record which
        // members the distillation keeps and skip formatting entirely.
        // (--distill never retains a group past eviction, so `retained` is
        // always `None` here.)
        if let Some(members) = self.config.distill {
            self.distill_take(group, members);
            return Ok(String::new());
        }
        let mut rollup = if group.count() >= self.config.min_collapse {
            match group.retained.take() {
                // Retained past eviction (lessence-940): the accumulator
                // was seeded from every member the group had at that
                // point and extended one rejoining member at a time since
                // — finalise it now, the one time this group is rendered,
                // instead of a batch scan `lines` can no longer support.
                Some(state) => self.rollup_computer.finalize_retained(
                    state,
                    group.template(),
                    &group.first().normalized,
                ),
                None => self.rollup_computer.compute(group),
            }
        } else {
            // A group that never reached min_collapse carries no rollup
            // either way; drop any seeded-but-unused accumulator with it.
            group.retained = None;
            if self.is_json_output() {
                self.json_uncomputed_variation_groups += 1;
            }
            BTreeMap::new()
        };
        // PII masking applies to rollup samples in every mode: the text
        // compact marker and the JSON `variation` field both surface raw
        // sample values, so both must mask.
        if let Some(z) = &self.sanitizer {
            mask_rollup_pii(&mut rollup, z);
        }
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
    pub(super) fn format_group_json(
        &mut self,
        group: &PatternGroup,
        variation: GroupRollup,
    ) -> Result<String> {
        let id = self.next_json_id;
        self.next_json_id += 1;

        for entry in variation.values() {
            let omitted = entry.distinct_count.saturating_sub(entry.samples.len());
            if entry.capped {
                self.json_capped_entries += 1;
            }
            if entry.capped || omitted > 0 {
                self.json_sampled_entries += 1;
            }
            self.json_omitted_values_lower_bound += omitted;
        }

        // `collapsed_groups` and `lines_saved` share one definition with
        // every other output mode: a collapsed group preserves 3 lines
        // (first + marker + last), exactly as the text renderer counts.
        // Agents cross-check the JSONL summary record against --stats-json
        // and the text footer, so the numbers must agree; the per-record
        // `count` field is the ground truth for any other arithmetic.
        if group.count() >= self.config.min_collapse && !self.config.essence_mode {
            self.stats.collapsed_groups += 1;
            self.stats.lines_saved += group.count().saturating_sub(3);
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
            // Detectors tokenize emails out of the normalized text, but
            // credential values they don't tokenize survive in it — mask
            // this field like first/last, not just the raw lines.
            normalized: self.maybe_mask_pii(group.template(), &group.first().tokens),
            first: LineRef {
                source: self.source_name(group.first_source_id),
                line: self.maybe_mask_pii(&group.first().original, &group.first().tokens),
                line_no: group.first_line_no,
            },
            last: LineRef {
                source: self.source_name(group.last_source_id),
                line: self.maybe_mask_pii(&group.last().original, &group.last().tokens),
                line_no: group.last_line_no,
            },
            time_range: TimeRange {
                first_seen: first_timestamp_in(&group.first().tokens),
                last_seen: first_timestamp_in(&group.last().tokens),
            },
            variation,
            nearest: group.nearest.clone(),
        };

        Ok(serde_json::to_string(&record)?)
    }

    #[cfg_attr(test, mutants::skip)] // PII masking interactions with essence_mode create equivalent mutants: sanitize_pii && !essence_mode branch is hard to distinguish from replacing the whole conditional
    pub(super) fn format_group(
        &mut self,
        group: &PatternGroup,
        rollup: &GroupRollup,
    ) -> Result<String> {
        if group.should_collapse(self.config.min_collapse) && !self.config.essence_mode {
            self.stats.collapsed_groups += 1;
            // First, summary, and last lines are output. saturating_sub
            // guards against a directly-constructed Config (the CLI floor
            // is 3, but `Config.min_collapse` is a public field) that lets
            // a 2-line group reach here and underflow count - 3.
            self.stats.lines_saved += group.count().saturating_sub(3);

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
                self.format_collapsed_line(
                    group.first(),
                    group.last(),
                    group.count() - 2, // Don't count first and last in collapse count
                )
            };

            // Format output: first line, collapsed summary, last line
            let mut result = String::new();
            let first_line: &str = if self.config.essence_mode {
                // Constitutional essence mode: the group's template
                group.template()
            } else {
                // Standard mode: use original text (with optional PII masking)
                &group.first().original
            };

            let first_line_output = self.maybe_mask_pii(first_line, &group.first().tokens);
            result.push_str(&first_line_output);
            result.push('\n');
            result.push_str(&collapsed_line);

            // Only add last line if it's different from first
            if group.count() > 1 {
                let last_line: &str = if self.config.essence_mode {
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

                    let last_line_output = self.maybe_mask_pii(last_line, &group.last().tokens);
                    result.push_str(&last_line_output);
                }
            }

            Ok(result)
        } else {
            // Output lines individually
            let mut result = String::new();

            if self.config.essence_mode {
                // In essence mode, show only the first occurrence of each unique pattern
                let line_text = self.maybe_mask_pii(group.template(), &group.first().tokens);
                result.push_str(&line_text);
                // Track lines saved (all duplicate lines in the group)
                if group.count() > 1 {
                    self.stats.lines_saved += group.count().saturating_sub(1);
                }
            } else {
                // Standard mode: output all lines individually (with optional PII masking)
                for (i, line) in group.lines.iter().enumerate() {
                    if i > 0 {
                        result.push('\n');
                    }

                    let line_output = self.maybe_mask_pii(&line.original, &line.tokens);
                    result.push_str(&line_output);
                }
            }
            Ok(result)
        }
    }

    /// Format a single summary line, optionally truncating to `max_width`.
    pub(super) fn format_summary_line(
        count: usize,
        representative: &str,
        max_width: Option<usize>,
    ) -> String {
        let prefix = format!("[{count}x] ");
        match max_width {
            Some(width) if prefix.len() + representative.len() > width => {
                let avail = width.saturating_sub(prefix.len() + 3); // 3 for "..."
                if avail > 20 {
                    // Snap the byte budget down to a UTF-8 char boundary so a
                    // multibyte char straddling `avail` can't panic the slice.
                    let mut end = avail;
                    while !representative.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{prefix}{}...", &representative[..end])
                } else {
                    format!("{prefix}{representative}")
                }
            }
            _ => format!("{prefix}{representative}"),
        }
    }

    /// Format the coverage message for stderr.
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

    /// Finish processing and output a one-line-per-pattern summary sorted by frequency.
    /// Uses the parallel pipeline for normalization, then merges groups with identical
    /// normalized text and displays representative original lines.
    #[cfg_attr(test, mutants::skip)] // Thin I/O wrapper: writes to stdout/stderr which cannot be captured in unit tests without refactoring
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

        // Output: one line per pattern with representative original line.
        // Like every other stdout path, a broken pipe (e.g. `| head`) is a
        // clean exit, not an error.
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let mut write_line = |s: String| -> Result<()> {
            crate::output::write_output(&mut handle, format_args!("{s}\n"))
        };
        for (count, representative) in &display {
            write_line(Self::format_summary_line(*count, representative, max_width))?;
        }

        if fit_truncated > 0 {
            write_line(format!(
                "... {fit_truncated} more patterns (remove --fit for full output)"
            ))?;
        }

        // Coverage info on stderr
        let shown_lines: usize = display.iter().map(|(c, _)| c).sum();
        eprintln!(
            "{}",
            Self::format_coverage_message(
                shown_count,
                total_patterns,
                shown_lines,
                self.stats.total_lines,
                was_capped,
            )
        );

        Ok(())
    }

    /// Emit the terminal summary record for a JSONL stream. Called once,
    /// after the main loop and `finish()` have drained all groups.
    /// Writes to `writer` (stdout in the main binary path) and ends with
    /// a trailing newline so the JSONL stream terminates cleanly.
    pub fn print_summary_json(&self, writer: &mut impl io::Write, elapsed: Duration) -> Result<()> {
        let record = SummaryRecord {
            record_type: "summary",
            stats: self.build_stats_json(elapsed),
            completeness: {
                let group_total = self.json_groups_total.unwrap_or(self.json_groups_emitted);
                let groups_complete = self.json_omitted_by_top == 0
                    && self.json_omitted_by_summary_cap == 0
                    && self.json_omitted_by_fit == 0
                    && self.json_retention_cap_hits == 0;
                let variation_complete = self.json_capped_entries == 0
                    && self.json_uncomputed_variation_groups == 0
                    && self.json_omitted_values_lower_bound == 0;
                Completeness {
                    complete: self.json_input_complete
                        && self.json_skipped_overlong_lines == 0
                        && groups_complete
                        && variation_complete,
                    input: InputCompleteness {
                        complete: self.json_input_complete && self.json_skipped_overlong_lines == 0,
                        processed_lines: self.stats.total_lines,
                        skipped_overlong_lines: Count::exact(self.json_skipped_overlong_lines),
                        unprocessed_after_max_lines: if self.json_max_lines_reached {
                            Count::unknown()
                        } else {
                            Count::exact(0)
                        },
                        failed_sources: if self.json_failed_sources {
                            Count::lower_bound(1)
                        } else {
                            Count::exact(0)
                        },
                    },
                    groups: GroupCompleteness {
                        complete: groups_complete,
                        emitted: self.json_groups_emitted,
                        total: Count::exact(group_total),
                        omitted_by_top: Count::exact(self.json_omitted_by_top),
                        omitted_by_summary_cap: Count::exact(self.json_omitted_by_summary_cap),
                        omitted_by_fit: Count::exact(self.json_omitted_by_fit),
                        fragmented_by_retention_cap: self.json_retention_cap_hits,
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

    /// Build the run's orientation briefing (src/briefing.rs) from
    /// accumulated stats. Shared by the text footer, `--preflight`, and
    /// `--explain`'s summary record.
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

        // Every input line must be represented in the template map exactly
        // once (by member count), unless the 8192-template cap was hit.
        debug_assert!(
            stats.template_counts.is_truncated()
                || stats.template_counts.total_members() == total_lines,
            "template_counts must account for every input line: {} != {total_lines}",
            stats.template_counts.total_members()
        );

        let mut tokens: Vec<crate::briefing::TokenClass> = stats
            .token_classes()
            .into_iter()
            .filter(|(_, _, count)| *count > 0)
            .map(|(class, bucket, occurrences)| {
                let (distinct, distinct_exact) = stats.cardinality_for(bucket);
                crate::briefing::TokenClass {
                    class,
                    occurrences,
                    distinct,
                    distinct_exact,
                }
            })
            .collect();
        tokens.sort_by(|a, b| {
            b.occurrences
                .cmp(&a.occurrences)
                .then_with(|| a.class.cmp(b.class))
        });

        // Duration/histogram both need the span as epoch seconds; compute
        // once and share.
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

    /// Build the JSON stats structure (testable, no I/O).
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

    #[cfg_attr(test, mutants::skip)] // Writes to stderr, cannot verify in unit tests without refactoring
    pub fn print_stats_json(&self, elapsed: Duration) -> Result<()> {
        let stats_json = self.build_stats_json(elapsed);
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        serde_json::to_writer(&mut handle, &stats_json)?;
        writeln!(handle)?;
        Ok(())
    }
    /// Emit the pretty-printed --preflight JSON report: the run's briefing.
    pub fn print_preflight_json<W: Write>(&self, writer: &mut W) -> Result<()> {
        let report = self.build_briefing();
        let json = serde_json::to_string_pretty(&report)?;
        writeln!(writer, "{json}")?;
        Ok(())
    }

    /// Emit the markdown document for the whole run. Group entries were
    /// buffered by the fold path into `markdown_entries`; this renders
    /// the header from run stats and wraps every entry in a code fence.
    pub fn emit_markdown<W: Write>(&self, writer: &mut W) -> Result<()> {
        let original_lines = self.stats.total_lines;
        let compressed_lines = self.stats.output_lines;
        // Same definition as every other mode: lines saved by folding
        // over total input lines.
        let compression_ratio = self.stats.compression_ratio();

        let mut write_line = |s: String| -> Result<()> {
            crate::output::write_output(writer, format_args!("{s}\n"))
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

        for (i, output) in self.markdown_entries.iter().enumerate() {
            // Untrusted log content always goes inside a fence whose
            // backtick run is longer than any run in the content, so it
            // cannot break out and inject markdown/HTML structure.
            if output.contains('+') && output.contains("similar") {
                write_line(format!("### Entry {} (Folded)\n", i + 1))?;
                write_line(format!("{}\n", markdown_code_fence(output)))?;
            } else {
                write_line(format!("{}\n", markdown_code_fence(output)))?;
            }
        }
        Ok(())
    }

    /// Legacy collapsed-line marker for groups whose rollup was skipped
    /// (small groups; see `format_group_dispatch`). Rendering concern,
    /// moved here from the normalizer.
    pub(super) fn format_collapsed_line(
        &self,
        first: &LogLine,
        last: &LogLine,
        count: usize,
    ) -> String {
        // Compact format: [+N similar, varying: TYPE]
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

    /// Which token kinds differ in value between a group's first and last
    /// line — the "varying: ..." list of the compact marker. Labels and
    /// comparable values are projections of the token taxonomy
    /// (`Token::facts` / `Token::value_string`).
    pub(super) fn summarize_variation_types(
        &self,
        first_tokens: &[Token],
        last_tokens: &[Token],
    ) -> Vec<String> {
        let mut types = std::collections::BTreeSet::new();

        // Kinds with `variation_compares_values == false` vary by
        // presence, not by value, so they compare under a fixed value.
        let get_token_info = |token: &Token| -> (&'static str, String) {
            let facts = token.facts();
            let value = if facts.variation_compares_values {
                token.value_string()
            } else {
                String::new()
            };
            (facts.display_label, value)
        };

        // Create maps of token types to values for first and last
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

        // Find token types that actually vary between first and last
        let all_types: std::collections::BTreeSet<&str> = first_values
            .keys()
            .chain(last_values.keys())
            .copied()
            .collect();

        for token_type in all_types {
            // In essence mode, ignore timestamp variations as they're tokenized for temporal independence
            if self.config.essence_mode && token_type == "timestamp" {
                continue;
            }

            let first_vals = first_values.get(token_type).cloned().unwrap_or_default();
            let last_vals = last_values.get(token_type).cloned().unwrap_or_default();

            // If the sets of values differ, this token type varies
            if first_vals != last_vals {
                types.insert(token_type.to_string());
            }
        }

        types.into_iter().collect()
    }

    /// Apply PII masking to a line when the run asks for it. Outside
    /// essence mode the full pass runs (emails via tokens, then the
    /// credential rules). Essence mode shows normalized text, which
    /// already tokenises emails out — but credential values are not
    /// tokens and survive normalization, so the credential rules must
    /// still run there.
    fn maybe_mask_pii(&self, line: &str, tokens: &[Token]) -> String {
        match &self.sanitizer {
            None => line.to_string(),
            // Essence mode has already tokenised emails, hosts and
            // addresses out of the line; what survives normalization is
            // found by scanning the text.
            Some(z) if self.config.essence_mode => z.mask_text(line),
            Some(z) => z.mask_line(line, tokens),
        }
    }
}

/// Mask PII inside rollup samples. The EMAIL entry's own samples collapse
/// to the mask token; occurrences of those email values embedded in other
/// entries' samples (quoted strings, structured messages) are replaced as
/// well, and every sample then passes through the same credential-class
/// masking as full lines so no output field can leak what the line
/// renderer would have masked.
fn mask_rollup_pii(rollup: &mut GroupRollup, z: &Sanitizer) {
    // Values of an enabled entity, so a sample of another type that quotes
    // one (a path holding an email, a message naming a host) masks too.
    let mut values: Vec<(String, String)> = Vec::new();
    for (name, entry) in rollup.iter() {
        if let Some((_, class)) = z.rollup_entity(name) {
            for sample in &entry.samples {
                values.push((sample.clone(), z.mask_sample(class, sample)));
            }
        }
    }
    for (name, entry) in rollup.iter_mut() {
        match z.rollup_entity(name) {
            Some((crate::sanitize::Action::Redact, class)) => {
                if !entry.samples.is_empty() {
                    entry.samples = vec![format!("<{class}>")];
                }
            }
            Some((crate::sanitize::Action::Pseudonym, class)) => {
                for sample in &mut entry.samples {
                    *sample = z.mask_sample(class, sample);
                }
            }
            None => {
                for sample in &mut entry.samples {
                    for (value, masked) in &values {
                        if sample.contains(value.as_str()) {
                            *sample = sample.replace(value.as_str(), masked);
                        }
                    }
                    *sample = z.mask_text(sample);
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
