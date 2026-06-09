use crate::config::Config;
use anyhow::Result;
#[allow(dead_code)]
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

/// Strip terminal escape sequences and neutralize bare C0 control bytes so that
/// untrusted log content cannot drive the operator's terminal when written
/// verbatim to stdout / `--summary` / `--top` / markdown.
///
/// The CSI-only predecessor (`\x1b\[[0-9;]*[a-zA-Z]`) let OSC sequences (window
/// title `\x1b]0;...\x07`, OSC 8 hyperlinks `\x1b]8;;URL\x07text\x1b]8;;\x07`),
/// DCS/APC/PM/SOS, the lone ESC, and bare C0 controls (CR `\r`, BS `\x08`)
/// through unchanged. This single shared sanitizer is the one place both the
/// binary (`main::strip_ansi_codes`) and the analyzer route through.
///
/// 8-bit C1 introducers (0x80-0x9F) cannot arrive here: input is read via
/// `BufRead::lines`, so any C1 byte would be invalid UTF-8 and never reach a
/// `String`. Only the 7-bit ESC-introduced forms plus bare C0 controls survive,
/// and all of those are matched below.
///
/// The pattern is a single ordered alternation the linear-time `regex` engine
/// handles without backtracking (no nested unbounded quantifiers). Order
/// matters: the OSC and DCS-family arms run before the generic CSI / lone-ESC
/// arm so a whole `ESC ] ... ST` / `ESC P ... ST` is consumed as one unit.
// In the library crate only tests call this; the binary crate re-includes
// this module via `mod analyzer` and routes main::strip_ansi_codes through it.
#[allow(dead_code)]
pub(crate) fn strip_terminal_escapes(text: &str) -> String {
    static ESCAPE_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(concat!(
            // OSC: ESC ] ... terminated by BEL or ST (ESC \), or unterminated to EOL.
            r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?",
            // DCS / SOS / PM / APC: ESC P|X|^|_ ... terminated by ST, or unterminated.
            r"|\x1b[P_^X][^\x1b]*(?:\x1b\\)?",
            // CSI: ESC [ params (0x30-0x3f) intermediates (0x20-0x2f) final (0x40-0x7e).
            r"|\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]",
            // Any remaining ESC sequence (two-byte like ESC c) or a lone trailing ESC.
            r"|\x1b.?",
            // Bare C0 controls that move the cursor / overwrite: CR, BS, VT, FF.
            // Tab (\x09) is intentionally preserved; \n cannot appear (lines split).
            r"|[\r\x08\x0b\x0c]",
        ))
        .unwrap()
    });
    ESCAPE_REGEX.replace_all(text, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- analyze ----

    // ---- update_pattern_counts ----

    // ---- generate_recommendations ----

    // ---- strip_terminal_escapes ----

    #[test]
    fn strip_ansi_removes_codes() {
        let input = "\x1b[31mERROR\x1b[0m: something failed";
        let result = strip_terminal_escapes(input);
        assert_eq!(result, "ERROR: something failed");
    }

    #[test]
    fn strip_ansi_no_codes() {
        let input = "plain text";
        assert_eq!(strip_terminal_escapes(input), "plain text");
    }

    #[test]
    fn strip_osc8_hyperlink() {
        // OSC 8 hyperlink: ESC]8;;URL BEL  visible-text  ESC]8;; BEL
        let input = "\x1b]8;;http://evil.example/\x07click here\x1b]8;;\x07";
        // Both OSC wrappers removed; only the visible label survives.
        assert_eq!(strip_terminal_escapes(input), "click here");
    }

    #[test]
    fn strip_osc8_hyperlink_st_terminated() {
        // Same hyperlink but terminated by ST (ESC \) instead of BEL.
        let input = "\x1b]8;;http://evil.example/\x1b\\click here\x1b]8;;\x1b\\";
        assert_eq!(strip_terminal_escapes(input), "click here");
    }

    #[test]
    fn strip_osc0_title_set() {
        // OSC 0 window-title rewrite must not reach the terminal.
        let input = "\x1b]0;you have been pwned\x07log message";
        assert_eq!(strip_terminal_escapes(input), "log message");
    }

    #[test]
    fn strip_cr_and_backspace() {
        // CR + backspace overwrite attack: "SAFE" then \r\b... to repaint "EVIL".
        let input = "SAFE\rEVIL\x08\x08\x08\x08done";
        assert_eq!(strip_terminal_escapes(input), "SAFEEVILdone");
    }

    #[test]
    fn strip_lone_trailing_escape() {
        // A lone ESC at end of line is removed, not left to swallow the next line.
        assert_eq!(strip_terminal_escapes("trailing\x1b"), "trailing");
    }

    #[test]
    fn strip_preserves_tab() {
        // Tab is legitimate content and must survive.
        assert_eq!(strip_terminal_escapes("a\tb"), "a\tb");
    }

    #[test]
    fn strip_dcs_sequence() {
        // DCS: ESC P ... ST must be removed entirely.
        let input = "before\x1bPq#0;1;2evil\x1b\\after";
        assert_eq!(strip_terminal_escapes(input), "beforeafter");
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
