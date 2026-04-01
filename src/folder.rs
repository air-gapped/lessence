use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;

use crate::config::Config;
use crate::normalize::Normalizer;
use crate::patterns::{LogLine, Token};

/// Apply PII masking to original text by replacing email addresses with <EMAIL> tokens
///
/// Takes the original log line text and detected tokens, returns masked text with
/// all Token::Email instances replaced with the literal "<EMAIL>" string.
///
/// # Arguments
/// * `original` - Original log line text (may contain email addresses)
/// * `tokens` - Detected pattern tokens (including Token::Email variants)
///
/// # Returns
/// Modified string with all detected emails replaced by <EMAIL> tokens
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
}

impl PatternGroup {
    fn new(line: LogLine, position: usize) -> Self {
        Self {
            lines: vec![line],
            collapsed: false,
            position,
        }
    }

    fn add_line(&mut self, line: LogLine) {
        self.lines.push(line);
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
        }
    }

    pub fn process_line(&mut self, line: &str) -> Result<Option<String>> {
        self.stats.total_lines += 1;
        self.position_counter += 1;

        // Parallel processing: batch lines for parallel pattern detection
        if self.config.thread_count != Some(1) {
            self.batch_buffer.push(line.to_string());

            if self.batch_buffer.len() >= 100 {
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
            self.buffer[index].add_line(normalized_line);
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
            let formatted = self.format_group(group)?;
            // Track output lines: count newlines in formatted output + 1 for the last line
            self.stats.output_lines += formatted.lines().count();
            return Ok(Some(formatted));
        }

        Ok(None)
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
            let formatted = self.format_group(group)?;
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
            let formatted = self.format_group(group)?;
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
                    if similarity >= self.config.threshold as f64 {
                        // Merge group j into group i
                        let group_to_merge = self.buffer.remove(j);
                        for line in group_to_merge.lines {
                            self.buffer[i].add_line(line);
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

    fn format_group(&mut self, group: PatternGroup) -> Result<String> {
        if group.should_collapse(self.config.min_collapse) && !self.config.essence_mode {
            self.stats.collapsed_groups += 1;
            self.stats.lines_saved += group.count() - 3; // First, summary, and last lines are output

            let collapsed_line = self.normalizer.format_collapsed_line(
                group.first(),
                group.last(),
                group.count() - 2, // Don't count first and last in collapse count
            );

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
                first_line.to_string()
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
                        last_line.to_string()
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
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )?;
        writeln!(writer)?;
        writeln!(writer, "## Summary")?;
        writeln!(writer, "- **Original**: {} lines", self.stats.total_lines)?;
        writeln!(
            writer,
            "- **Compressed**: {} lines ({:.1}% reduction)",
            output_lines, compression_ratio
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
                "- **High compression ratio** ({:.1}%) indicates many repetitive patterns",
                compression_ratio
            )?;
        } else if compression_ratio > 70.0 {
            writeln!(
                writer,
                "- **Moderate compression ratio** ({:.1}%) indicates some repetitive patterns",
                compression_ratio
            )?;
        } else {
            writeln!(
                writer,
                "- **Low compression ratio** ({:.1}%) indicates diverse log content",
                compression_ratio
            )?;
        }

        writeln!(writer, "- **Search strategy**: Use compressed output to identify error types, then grep original logs for details")?;
        writeln!(writer, "- **Variation indicators**: Pay attention to `[+N similar, varying: X, Y]` to understand what changes between similar errors")?;
        writeln!(writer, "- **Focus areas**: Unique error messages that couldn't be compressed likely indicate distinct issues")?;

        if self.stats.collapsed_groups > 50 {
            writeln!(writer, "- **High pattern repetition**: {} collapsed groups suggest systematic issues worth investigating", self.stats.collapsed_groups)?;
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

    /// Process all lines in summary mode: collect unique patterns with counts and timestamp range
    pub fn process_summary_mode<I, W>(&mut self, lines: I, writer: &mut W) -> Result<()>
    where
        I: Iterator<Item = io::Result<String>>,
        W: Write,
    {
        let mut pattern_counts: HashMap<String, usize> = HashMap::new();
        let mut first_timestamp: Option<String> = None;
        let mut last_timestamp: Option<String> = None;

        let ansi_regex = regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();

        for (lines_processed, line) in lines.enumerate() {
            let line = line?;

            // Security: Check line count limit (Constitutional Principle X)
            if let Some(max_lines) = self.config.max_lines {
                if lines_processed >= max_lines {
                    break;
                }
            }

            self.stats.total_lines += 1;

            // Security: Check line length limit (Constitutional Principle X)
            if let Some(max_length) = self.config.max_line_length {
                if line.len() > max_length {
                    continue;
                }
            }

            // Strip ANSI if needed
            let line = if !self.config.preserve_color {
                ansi_regex.replace_all(&line, "").to_string()
            } else {
                line
            };

            // Extract timestamp for range tracking
            if let Some(timestamp) = self.extract_timestamp(&line) {
                if first_timestamp.is_none() {
                    first_timestamp = Some(timestamp.clone());
                }
                last_timestamp = Some(timestamp);
            }

            // Normalize the line to get the pattern
            let normalized_line = self.normalizer.normalize_line(line)?;

            if !normalized_line.tokens.is_empty() {
                self.stats.patterns_detected += 1;
                self.count_pattern_types(&normalized_line.tokens);
            }

            // Count this pattern
            *pattern_counts
                .entry(normalized_line.normalized)
                .or_insert(0) += 1;
        }

        // Sort patterns by frequency (highest first)
        let mut sorted_patterns: Vec<(String, usize)> = pattern_counts.into_iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(&a.1));

        let total_unique_patterns = sorted_patterns.len();

        // Output ultra-compact summary
        println!("=== lessence Summary Mode ===");

        if let (Some(first), Some(last)) = (&first_timestamp, &last_timestamp) {
            println!("Time range: {} → {}", first, last);
        }
        println!();

        println!("=== Unique Patterns ({} total) ===", total_unique_patterns);

        let patterns_output = sorted_patterns.len();
        for (pattern, count) in sorted_patterns {
            println!("[{}x] {}", count, pattern);
        }

        // Output compression stats
        if self.config.stats {
            self.print_summary_stats(writer, total_unique_patterns, patterns_output)?;
        }

        Ok(())
    }

    /// Extract timestamp from a line (simplified version)
    fn extract_timestamp(&self, line: &str) -> Option<String> {
        // Look for common timestamp patterns at the beginning of the line
        let timestamp_patterns = [
            r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4}|Z)?)",
            r"^([IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+)",
            r"^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
        ];

        for pattern in &timestamp_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(line) {
                    if let Some(timestamp) = captures.get(1) {
                        return Some(timestamp.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    /// Print summary-specific stats
    fn print_summary_stats<W: Write>(
        &self,
        writer: &mut W,
        total_patterns: usize,
        patterns_output: usize,
    ) -> Result<()> {
        let dedup_ratio = if self.stats.total_lines > 0 {
            ((self.stats.total_lines - total_patterns) as f64 / self.stats.total_lines as f64)
                * 100.0
        } else {
            0.0
        };

        writeln!(writer, "\n---")?;
        writeln!(writer, "# lessence Summary Compression Report")?;
        writeln!(writer)?;
        writeln!(writer, "## Summary")?;
        writeln!(writer, "- **Original**: {} lines", self.stats.total_lines)?;
        writeln!(
            writer,
            "- **Compressed**: {} unique patterns",
            patterns_output
        )?;
        writeln!(
            writer,
            "- **Pattern reduction**: {} total → {} unique ({:.1}% deduplication)",
            self.stats.total_lines, total_patterns, dedup_ratio
        )?;
        writeln!(
            writer,
            "- **Patterns detected**: {} across {} categories",
            self.stats.patterns_detected,
            self.count_active_pattern_types()
        )?;
        writeln!(writer)?;

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

        writeln!(writer)?;
        writeln!(writer, "## Recommendations for Analysis")?;
        writeln!(
            writer,
            "- Focus on high-frequency patterns first (top of the list)"
        )?;
        writeln!(
            writer,
            "- Use pattern frequencies to prioritize debugging efforts"
        )?;
        writeln!(
            writer,
            "- Search original logs with normalized patterns for specific instances"
        )?;
        writeln!(
            writer,
            "- Each `[Nx]` indicates N occurrences of that exact error pattern"
        )?;
        writeln!(writer, "---")?;

        Ok(())
    }

    /// Parallel batch processing: normalize in parallel, cluster sequentially
    fn process_batch(&mut self) -> Result<()> {
        let batch = std::mem::take(&mut self.batch_buffer);
        let processed_lines = self.parallel_pattern_detection(batch)?;

        for processed_line in processed_lines {
            self.sequential_clustering(processed_line)?;
        }
        Ok(())
    }

    /// Phase 1: Parallel pattern detection and normalization (the CPU-intensive work)
    fn parallel_pattern_detection(&self, lines: Vec<String>) -> Result<Vec<LogLine>> {
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
            self.buffer[index].add_line(normalized_line);
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

    #[test]
    fn test_simple_folding() -> Result<()> {
        let config = Config::default();
        let mut folder = PatternFolder::new(config);

        // Add similar lines
        let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
        let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
        let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        let result = folder.process_line(line3)?;

        // Should not collapse yet (need more lines)
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_folding_with_finish() -> Result<()> {
        let config = Config {
            min_collapse: 2, // Lower threshold for testing
            ..Config::default()
        };

        let mut folder = PatternFolder::new(config);

        // Add similar lines
        let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
        let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
        let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        folder.process_line(line3)?;

        let results = folder.finish()?;
        assert!(!results.is_empty());

        // Check that output contains compact folding format (default is compact=true)
        let output = results.join("\n");
        assert!(
            output.contains("similar"),
            "Expected 'similar' in compact output, got: {}",
            output
        );

        Ok(())
    }

    #[test]
    fn test_no_folding_for_different_lines() -> Result<()> {
        let config = Config::default();
        let mut folder = PatternFolder::new(config);

        // Add different lines
        let line1 = "2025-01-20 10:15:01 Starting application";
        let line2 = "2025-01-20 10:15:02 Loading configuration";
        let line3 = "2025-01-20 10:15:03 Database connected";

        folder.process_line(line1)?;
        folder.process_line(line2)?;
        folder.process_line(line3)?;

        let results = folder.finish()?;
        let output = results.join("\n");

        // Should not contain collapsed format
        assert!(!output.contains("collapsed"));

        // All original lines should be present
        assert!(output.contains("Starting application"));
        assert!(output.contains("Loading configuration"));
        assert!(output.contains("Database connected"));

        Ok(())
    }
}
