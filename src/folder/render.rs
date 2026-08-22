//! Rendering: finished fold results -> bytes, for every output mode.
//!
//! This module owns the entire "render a finished group set plus run
//! metadata" surface: the text fold output, the JSONL group and summary
//! records, the --summary lines, the markdown document, and both stats
//! reports. The folding engine in `mod.rs` produces groups as data; the
//! methods here are the only place that data becomes output.

use super::{
    BTreeMap, Completeness, Count, Duration, GroupCompleteness, GroupRecord, GroupRollup,
    InputCompleteness, LineRef, PatternFolder, PatternGroup, ROLLUP_TEXT_SAMPLE_THRESHOLD, Result,
    StatsJson, SummaryRecord, TimeRange, Token, VariationCompleteness, Write, apply_pii_masking,
    first_timestamp_in, io, render_compact_marker, token_type_name,
};

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
    pub(super) fn format_group_dispatch(&mut self, group: &PatternGroup) -> Result<String> {
        let mut rollup = if group.count() >= self.config.min_collapse {
            self.rollup_computer.compute(group)
        } else {
            if self.is_json_output() {
                self.json_uncomputed_variation_groups += 1;
            }
            BTreeMap::new()
        };
        // PII masking applies to rollup samples in every mode: the text
        // compact marker and the JSON `variation` field both surface raw
        // sample values, so both must mask.
        if self.config.sanitize_pii && !self.config.essence_mode {
            mask_rollup_emails(&mut rollup);
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
            self.stats.lines_saved += group.count().saturating_sub(1);
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
                    self.stats.lines_saved += group.count().saturating_sub(1);
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
            match writeln!(handle, "{s}") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                }
                Err(e) => Err(e.into()),
            }
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
                pattern_hits: self.stats.pattern_hits(),
            },
            completeness: {
                let group_total = self.json_groups_total.unwrap_or(self.json_groups_emitted);
                let groups_complete = self.json_omitted_by_top == 0
                    && self.json_omitted_by_summary_cap == 0
                    && self.json_omitted_by_fit == 0;
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
        };
        serde_json::to_writer(&mut *writer, &record)?;
        writeln!(writer)?;
        Ok(())
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
            crate::report::timestamp().format("%Y-%m-%dT%H:%M:%SZ")
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

        for (label, count, description) in self.stats.pattern_counters() {
            if count > 0 {
                writeln!(writer, "| {label} | {count} | {description} |")?;
            }
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
    pub(super) fn build_stats_json(&self, elapsed: Duration) -> StatsJson {
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
    /// Emit the markdown document for the whole run. Group entries were
    /// buffered by the fold path into `markdown_entries`; this renders
    /// the header from run stats and wraps every entry in a code fence.
    pub fn emit_markdown<W: Write>(&self, writer: &mut W) -> Result<()> {
        let original_lines = self.stats.total_lines;
        let compressed_lines = self.stats.output_lines;
        let compression_ratio = if original_lines > 0 {
            100.0 * original_lines.saturating_sub(compressed_lines) as f64 / original_lines as f64
        } else {
            0.0
        };

        let mut write_line = |s: String| -> Result<()> {
            match writeln!(writer, "{s}") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                }
                Err(e) => Err(e.into()),
            }
        };

        write_line("# Log Analysis".to_string())?;
        write_line(format!(
            "*Generated by lessence v{} on {}*\n",
            env!("CARGO_PKG_VERSION"),
            crate::report::timestamp().format("%Y-%m-%dT%H:%M:%SZ")
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

    /// Apply PII masking to a line when the run asks for it. Same
    /// condition as the text renderer: essence mode already shows
    /// tokenised text, so masking applies only outside it.
    fn maybe_mask_pii(&self, line: &str, tokens: &[Token]) -> String {
        if self.config.sanitize_pii && !self.config.essence_mode {
            apply_pii_masking(line, tokens)
        } else {
            line.to_string()
        }
    }
}

/// Mask email addresses inside rollup samples. The EMAIL entry's own
/// samples collapse to the mask token; occurrences of those email values
/// embedded in other entries' samples (quoted strings, structured
/// messages) are replaced as well. Uses only exact values the rollup
/// itself observed -- no additional pattern matching.
fn mask_rollup_emails(rollup: &mut GroupRollup) {
    let emails: Vec<String> = rollup
        .get("EMAIL")
        .map(|entry| entry.samples.clone())
        .unwrap_or_default();
    for (name, entry) in rollup.iter_mut() {
        if *name == "EMAIL" {
            if !entry.samples.is_empty() {
                entry.samples = vec!["<EMAIL>".to_string()];
            }
        } else {
            for sample in &mut entry.samples {
                for email in &emails {
                    if sample.contains(email.as_str()) {
                        *sample = sample.replace(email.as_str(), "<EMAIL>");
                    }
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
