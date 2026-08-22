use crate::config::Config;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub total_lines: usize,
    pub estimated_compression: CompressionEstimates,
    pub pattern_distribution: PatternDistribution,
    pub recommendations: Vec<String>,
    pub sample_patterns: SamplePatterns,
}

/// Since the per-scenario compression simulation was removed (it was dead
/// code), all four fields carry the same measured value. They are kept so
/// the --preflight JSON schema stays stable for existing consumers.
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

        let output_lines = stats.total_lines.saturating_sub(stats.lines_saved);

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
