use anyhow::Result;
#[allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};

use crate::config::Config;
use crate::normalize::Normalizer;
use crate::patterns::{LogLine, Token};

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub total_lines: usize,
    pub estimated_compression: CompressionEstimates,
    pub pattern_distribution: PatternDistribution,
    pub recommendations: Vec<String>,
    pub sample_patterns: SamplePatterns,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompressionEstimates {
    pub default: String,
    pub with_paths: String,
    pub with_numbers: String,
    pub aggressive: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PatternDistribution {
    pub timestamps: usize,
    pub ips: usize,
    pub paths: usize,
    pub hashes: usize,
    pub numbers: usize,
    pub uuids: usize,
    pub pids: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SamplePatterns {
    pub paths: Vec<String>,
    pub numbers: Vec<String>,
    pub timestamps: Vec<String>,
    pub ips: Vec<String>,
}

pub struct LogAnalyzer;

impl LogAnalyzer {
    #[allow(dead_code)]
    pub fn analyze<R: Read>(reader: R, config: &Config) -> Result<AnalysisResult> {
        let buf_reader = BufReader::new(reader);
        let mut total_lines = 0;
        let mut pattern_counts = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };

        let mut sample_patterns = SamplePatterns {
            paths: Vec::new(),
            numbers: Vec::new(),
            timestamps: Vec::new(),
            ips: Vec::new(),
        };

        let mut log_lines = Vec::new();
        let normalizer = Normalizer::new(config.clone());

        // Analyze each line
        for line in buf_reader.lines() {
            let mut line = line?;
            total_lines += 1;

            // Strip ANSI color codes by default (unless --preserve-color)
            if !config.preserve_color {
                line = Self::strip_ansi_codes(&line);
            }

            // Normalize the line using the proper normalizer
            let log_line = normalizer.normalize_line(line)?;

            // Update pattern counts and samples
            Self::update_pattern_counts(
                &log_line.tokens,
                &mut pattern_counts,
                &mut sample_patterns,
            );

            log_lines.push(log_line);

            // Progress indicator for very large files
            if total_lines % 50000 == 0 {
                eprintln!("Analyzed {total_lines} lines...");
            }
        }

        // Calculate compression estimates
        let compression_estimates = Self::calculate_compression_estimates(
            total_lines,
            &log_lines,
            &normalizer,
            &pattern_counts,
        );

        // Generate recommendations
        let recommendations = Self::generate_recommendations(&pattern_counts, total_lines);

        // Limit sample sizes
        sample_patterns.paths.truncate(5);
        sample_patterns.numbers.truncate(5);
        sample_patterns.timestamps.truncate(3);
        sample_patterns.ips.truncate(5);

        Ok(AnalysisResult {
            total_lines,
            estimated_compression: compression_estimates,
            pattern_distribution: pattern_counts,
            recommendations,
            sample_patterns,
        })
    }

    fn update_pattern_counts(
        tokens: &[Token],
        counts: &mut PatternDistribution,
        samples: &mut SamplePatterns,
    ) {
        for token in tokens {
            match token {
                Token::Timestamp(ts) => {
                    counts.timestamps += 1;
                    if samples.timestamps.len() < 5 && !samples.timestamps.contains(ts) {
                        samples.timestamps.push(ts.clone());
                    }
                }
                Token::IPv4(ip) | Token::IPv6(ip) => {
                    counts.ips += 1;
                    if samples.ips.len() < 5 && !samples.ips.contains(ip) {
                        samples.ips.push(ip.clone());
                    }
                }
                Token::Port(_) => counts.ips += 1, // Count ports with IPs
                Token::Hash(_, _) => counts.hashes += 1,
                Token::Uuid(_) => counts.uuids += 1,
                Token::Pid(_) => counts.pids += 1,
                Token::Path(path) => {
                    counts.paths += 1;
                    if samples.paths.len() < 5 && !samples.paths.contains(path) {
                        samples.paths.push(path.clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn calculate_compression_estimates(
        total_lines: usize,
        log_lines: &[LogLine],
        normalizer: &Normalizer,
        _patterns: &PatternDistribution,
    ) -> CompressionEstimates {
        // Simulate actual compression by grouping similar lines
        let default_compressed = Self::simulate_compression(log_lines, normalizer, 85, 4);
        let paths_compressed = Self::simulate_compression_with_paths(log_lines, normalizer, 85, 4);
        let aggressive_compressed = Self::simulate_compression(log_lines, normalizer, 70, 3);

        let default_ratio = 1.0 - (default_compressed as f64 / total_lines as f64);
        let paths_ratio = 1.0 - (paths_compressed as f64 / total_lines as f64);
        let aggressive_ratio = 1.0 - (aggressive_compressed as f64 / total_lines as f64);

        CompressionEstimates {
            default: format!(
                "{:.1}% ({} lines)",
                default_ratio * 100.0,
                default_compressed
            ),
            with_paths: format!("{:.1}% ({} lines)", paths_ratio * 100.0, paths_compressed),
            with_numbers: format!(
                "{:.1}% ({} lines)",
                aggressive_ratio * 100.0,
                aggressive_compressed
            ),
            aggressive: format!(
                "{:.1}% ({} lines)",
                aggressive_ratio * 100.0,
                aggressive_compressed
            ),
        }
    }

    fn simulate_compression(
        log_lines: &[LogLine],
        normalizer: &Normalizer,
        threshold: u8,
        min_collapse: usize,
    ) -> usize {
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut processed = vec![false; log_lines.len()];

        for i in 0..log_lines.len() {
            if processed[i] {
                continue;
            }

            let mut group = vec![i];
            processed[i] = true;

            // Find similar lines
            for j in (i + 1)..log_lines.len() {
                if processed[j] {
                    continue;
                }

                let similarity = normalizer.similarity_score(&log_lines[i], &log_lines[j]);
                if similarity >= f64::from(threshold) {
                    group.push(j);
                    processed[j] = true;
                }
            }

            groups.push(group);
        }

        // Count output lines (groups with min_collapse+ lines become 1 summary line)
        groups
            .iter()
            .map(|group| {
                if group.len() >= min_collapse {
                    1 // Summary line
                } else {
                    group.len() // Original lines
                }
            })
            .sum()
    }

    fn simulate_compression_with_paths(
        log_lines: &[LogLine],
        _normalizer: &Normalizer,
        threshold: u8,
        min_collapse: usize,
    ) -> usize {
        // Create a config with paths enabled for simulation
        let paths_config = Config {
            normalize_paths: true,
            ..Config::default()
        };
        let paths_normalizer = Normalizer::new(paths_config);

        // Re-normalize with paths enabled
        let path_normalized: Vec<LogLine> = log_lines
            .iter()
            .map(|line| {
                paths_normalizer
                    .normalize_line(line.original.clone())
                    .unwrap_or_else(|_| line.clone())
            })
            .collect();

        Self::simulate_compression(&path_normalized, &paths_normalizer, threshold, min_collapse)
    }

    fn generate_recommendations(patterns: &PatternDistribution, total_lines: usize) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Path analysis
        if patterns.paths > total_lines / 4 {
            recommendations.push(
                "--paths: High path repetition detected, consider enabling for better compression"
                    .to_string(),
            );
        } else if patterns.paths > 0 {
            recommendations
                .push("--paths: Some paths detected, review samples before enabling".to_string());
        }

        // High timestamp frequency
        if patterns.timestamps > total_lines * 8 / 10 {
            recommendations
                .push("High timestamp frequency - excellent for default compression".to_string());
        }

        // IP analysis
        if patterns.ips > total_lines / 2 {
            recommendations
                .push("Many IP addresses detected - good candidate for lessence".to_string());
        }

        // Hash analysis
        if patterns.hashes > total_lines / 3 {
            recommendations.push(
                "High hash frequency detected - significant compression possible".to_string(),
            );
        }

        // General recommendations
        if patterns.timestamps + patterns.ips + patterns.hashes < total_lines / 10 {
            recommendations.push(
                "Warning: Low pattern repetition detected, compression may be minimal".to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations
                .push("Standard compression recommended - use default settings".to_string());
        }

        recommendations
    }

    fn strip_ansi_codes(text: &str) -> String {
        static ANSI_REGEX: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap());
        ANSI_REGEX.replace_all(text, "").to_string()
    }

    /// Create analysis result from processed folder statistics (for preflight mode)
    /// Create analysis result from processed folder statistics (for preflight mode)
    pub fn from_folder_stats(
        folder: &crate::folder::PatternFolder,
        _config: &Config,
    ) -> Result<AnalysisResult> {
        let stats = folder.get_stats();

        let patterns = PatternDistribution {
            timestamps: stats.timestamps,
            ips: stats.ips,
            paths: stats.paths,
            hashes: stats.hashes,
            numbers: stats.durations, // Use durations as numbers
            uuids: stats.uuids,
            pids: stats.pids,
        };

        let compression_ratio = if stats.total_lines > 0 {
            (stats.lines_saved as f64 / stats.total_lines as f64) * 100.0
        } else {
            0.0
        };

        let output_lines = stats.total_lines - stats.lines_saved;

        let recommendations = vec![
            format!("Compression achieved: {:.1}%", compression_ratio),
            format!(
                "Output size: {} lines (from {} original)",
                output_lines, stats.total_lines
            ),
            if compression_ratio > 90.0 {
                "Excellent compression - highly recommended for processing".to_string()
            } else if compression_ratio > 70.0 {
                "Good compression - recommended for processing".to_string()
            } else {
                "Low compression - consider if processing is beneficial".to_string()
            },
        ];

        Ok(AnalysisResult {
            total_lines: stats.total_lines,
            estimated_compression: CompressionEstimates {
                default: format!("{compression_ratio:.1}% compression"),
                with_paths: format!("{compression_ratio:.1}% compression"),
                with_numbers: format!("{compression_ratio:.1}% compression"),
                aggressive: format!("{compression_ratio:.1}% compression"),
            },
            pattern_distribution: patterns,
            recommendations,
            sample_patterns: SamplePatterns {
                paths: vec![],
                numbers: vec![],
                timestamps: vec![],
                ips: vec![],
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn default_config() -> Config {
        Config::default()
    }

    // ---- analyze ----

    #[test]
    fn analyze_empty_input() {
        let input = Cursor::new("");
        let result = LogAnalyzer::analyze(input, &default_config()).unwrap();
        assert_eq!(result.total_lines, 0);
    }

    #[test]
    fn analyze_single_line() {
        let input = Cursor::new("2024-01-01 10:00:00 error at 10.0.0.1");
        let result = LogAnalyzer::analyze(input, &default_config()).unwrap();
        assert_eq!(result.total_lines, 1);
        assert!(result.pattern_distribution.timestamps > 0 || result.pattern_distribution.ips > 0);
    }

    #[test]
    fn analyze_multiple_lines() {
        let input = Cursor::new(
            "2024-01-01 10:00:00 error at 10.0.0.1\n\
             2024-01-01 10:00:01 error at 10.0.0.2\n\
             2024-01-01 10:00:02 error at 10.0.0.3\n",
        );
        let result = LogAnalyzer::analyze(input, &default_config()).unwrap();
        assert_eq!(result.total_lines, 3);
    }

    #[test]
    fn analyze_compression_estimates_populated() {
        let lines: Vec<String> = (0..20)
            .map(|i| format!("2024-01-01 10:00:{i:02} error at 10.0.0.{}", i % 256))
            .collect();
        let input = Cursor::new(lines.join("\n"));
        let result = LogAnalyzer::analyze(input, &default_config()).unwrap();
        assert!(!result.estimated_compression.default.is_empty());
        assert!(!result.estimated_compression.aggressive.is_empty());
    }

    // ---- update_pattern_counts ----

    #[test]
    fn update_counts_timestamp() {
        let mut counts = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let mut samples = SamplePatterns {
            paths: vec![],
            numbers: vec![],
            timestamps: vec![],
            ips: vec![],
        };
        LogAnalyzer::update_pattern_counts(
            &[Token::Timestamp("2024-01-01".into())],
            &mut counts,
            &mut samples,
        );
        assert_eq!(counts.timestamps, 1);
        assert_eq!(samples.timestamps.len(), 1);
    }

    #[test]
    fn update_counts_ip() {
        let mut counts = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let mut samples = SamplePatterns {
            paths: vec![],
            numbers: vec![],
            timestamps: vec![],
            ips: vec![],
        };
        LogAnalyzer::update_pattern_counts(
            &[Token::IPv4("10.0.0.1".into())],
            &mut counts,
            &mut samples,
        );
        assert_eq!(counts.ips, 1);
        assert_eq!(samples.ips.len(), 1);
    }

    #[test]
    fn update_counts_path() {
        let mut counts = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let mut samples = SamplePatterns {
            paths: vec![],
            numbers: vec![],
            timestamps: vec![],
            ips: vec![],
        };
        LogAnalyzer::update_pattern_counts(
            &[Token::Path("/var/log".into())],
            &mut counts,
            &mut samples,
        );
        assert_eq!(counts.paths, 1);
        assert_eq!(samples.paths.len(), 1);
    }

    #[test]
    fn update_counts_samples_capped_at_5() {
        let mut counts = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let mut samples = SamplePatterns {
            paths: vec![],
            numbers: vec![],
            timestamps: vec![],
            ips: vec![],
        };
        for i in 0..10 {
            LogAnalyzer::update_pattern_counts(
                &[Token::IPv4(format!("10.0.0.{i}"))],
                &mut counts,
                &mut samples,
            );
        }
        assert_eq!(counts.ips, 10);
        assert_eq!(samples.ips.len(), 5, "samples should be capped at 5");
    }

    // ---- generate_recommendations ----

    #[test]
    fn recommendations_high_paths() {
        let patterns = PatternDistribution {
            timestamps: 0,
            ips: 0,
            paths: 30,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let recs = LogAnalyzer::generate_recommendations(&patterns, 100);
        assert!(recs.iter().any(|r| r.contains("--paths")));
    }

    #[test]
    fn recommendations_high_timestamps() {
        let patterns = PatternDistribution {
            timestamps: 90,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let recs = LogAnalyzer::generate_recommendations(&patterns, 100);
        assert!(recs.iter().any(|r| r.contains("timestamp")));
    }

    #[test]
    fn recommendations_low_patterns() {
        let patterns = PatternDistribution {
            timestamps: 1,
            ips: 0,
            paths: 0,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let recs = LogAnalyzer::generate_recommendations(&patterns, 100);
        assert!(
            recs.iter()
                .any(|r| r.contains("Warning") || r.contains("minimal"))
        );
    }

    #[test]
    fn recommendations_empty_gets_default() {
        let patterns = PatternDistribution {
            timestamps: 50,
            ips: 30,
            paths: 10,
            hashes: 0,
            numbers: 0,
            uuids: 0,
            pids: 0,
        };
        let recs = LogAnalyzer::generate_recommendations(&patterns, 100);
        assert!(!recs.is_empty());
    }

    // ---- strip_ansi_codes ----

    #[test]
    fn strip_ansi_removes_codes() {
        let input = "\x1b[31mERROR\x1b[0m: something failed";
        let result = LogAnalyzer::strip_ansi_codes(input);
        assert_eq!(result, "ERROR: something failed");
    }

    #[test]
    fn strip_ansi_no_codes() {
        let input = "plain text";
        assert_eq!(LogAnalyzer::strip_ansi_codes(input), "plain text");
    }

    // ---- from_folder_stats ----

    #[test]
    fn from_folder_stats_basic() {
        let config = Config {
            thread_count: Some(1),
            min_collapse: 3,
            ..Config::default()
        };
        let mut folder = crate::folder::PatternFolder::new(config.clone());
        // Process some lines to build stats
        folder.process_line("2024-01-01 10:00:00 error").unwrap();
        folder.process_line("2024-01-01 10:00:01 error").unwrap();

        let result = LogAnalyzer::from_folder_stats(&folder, &config).unwrap();
        assert_eq!(result.total_lines, 2);
        assert!(!result.recommendations.is_empty());
    }
}
