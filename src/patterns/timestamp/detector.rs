// Unified Timestamp Detection Engine
// Constitutional requirement: Replace both timestamp.rs and essence/processor.rs

use super::{DetectionResult, TimestampMatch, TimestampRegistry, Token};
use std::sync::LazyLock;

/// Central timestamp pattern detection system
/// Replaces both src/patterns/timestamp.rs and src/essence/processor.rs patterns
pub struct UnifiedTimestampDetector;

/// Static registry for efficient pattern access
static TIMESTAMP_REGISTRY: LazyLock<TimestampRegistry> = LazyLock::new(TimestampRegistry::new);

impl UnifiedTimestampDetector {
    /// Primary detection interface - replaces TimestampDetector::detect_and_replace
    ///
    /// Constitutional requirements:
    /// - Support all 30+ timestamp formats without shortcuts
    /// - Thread-safe for parallel processing
    /// - Preserve 100% of unique information
    /// - Replace only longest/most specific match when overlaps occur
    /// - Unix timestamps lowest priority to prevent false positives
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let result = Self::detect_with_metadata(text);

        // Convert to legacy format for compatibility
        let tokens = result
            .matches
            .iter()
            .map(|m| Token::Timestamp(m.original.clone()))
            .collect();

        (result.normalized_text, tokens)
    }

    /// Advanced detection interface for detailed analysis
    ///
    /// Provides full detection metadata for debugging and validation
    pub fn detect_with_metadata(text: &str) -> DetectionResult {
        // Quick pre-filter to avoid expensive regex operations
        if !Self::has_timestamp_indicators(text) {
            return DetectionResult {
                normalized_text: text.to_string(),
                matches: Vec::new(),
            };
        }

        let registry = &*TIMESTAMP_REGISTRY;
        let patterns = registry.get_patterns();

        let mut all_matches = Vec::new();

        // Find all possible matches
        for pattern in patterns {
            for regex_match in pattern.regex.find_iter(text) {
                let timestamp_match = TimestampMatch {
                    original: regex_match.as_str().to_string(),
                    start_pos: regex_match.start(),
                    end_pos: regex_match.end(),
                    priority: pattern.priority.clone(),
                };
                all_matches.push(timestamp_match);
            }
        }

        // Sort by position for overlap resolution
        all_matches.sort_by_key(|m| m.start_pos);

        // Resolve overlaps - select longest/most specific match
        let resolved_matches = Self::resolve_overlaps(all_matches);

        // Apply replacements
        let normalized_text = Self::apply_replacements(text, &resolved_matches);

        DetectionResult {
            normalized_text,
            matches: resolved_matches,
        }
    }

    /// Fast pre-filter for timestamp indicators
    fn has_timestamp_indicators(text: &str) -> bool {
        text.contains(':')
            && (text.contains("20") || // Years 20xx
            text.contains("19") || // Years 19xx
            text.contains('-') ||  // Date separators
            text.contains('T') ||  // ISO 8601 separator
            text.contains('[') ||  // Log brackets
            // Kubernetes/Go log levels
            text.contains("I09") || text.contains("W09") || text.contains("E09") || text.contains("F09") ||
            text.contains("I10") || text.contains("W10") || text.contains("E10") || text.contains("F10") ||
            text.contains("I11") || text.contains("W11") || text.contains("E11") || text.contains("F11") ||
            text.contains("I12") || text.contains("W12") || text.contains("E12") || text.contains("F12") ||
            // Month names
            text.contains("Jan") || text.contains("Feb") || text.contains("Mar") ||
            text.contains("Apr") || text.contains("May") || text.contains("Jun") ||
            text.contains("Jul") || text.contains("Aug") || text.contains("Sep") ||
            text.contains("Oct") || text.contains("Nov") || text.contains("Dec"))
    }

    /// Resolve overlapping matches using longest-match-first rule
    fn resolve_overlaps(mut matches: Vec<TimestampMatch>) -> Vec<TimestampMatch> {
        if matches.is_empty() {
            return matches;
        }

        // Sort by priority first (most specific patterns first)
        matches.sort_by(|a, b| {
            a.priority
                .effective_score()
                .cmp(&b.priority.effective_score())
        });

        let mut resolved = Vec::new();
        let mut used_positions = Vec::new();

        for candidate in matches {
            let candidate_range = candidate.start_pos..candidate.end_pos;

            // Check if this candidate overlaps with any already selected match
            let overlaps = used_positions
                .iter()
                .any(|used_range: &std::ops::Range<usize>| {
                    candidate_range.start < used_range.end && candidate_range.end > used_range.start
                });

            if !overlaps {
                used_positions.push(candidate_range);
                resolved.push(candidate);
            }
        }

        // Sort resolved matches by position for consistent output
        resolved.sort_by_key(|m| m.start_pos);
        resolved
    }

    /// Apply timestamp replacements to text
    fn apply_replacements(text: &str, matches: &[TimestampMatch]) -> String {
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Apply replacements in reverse order to maintain positions
        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.start_pos));

        for timestamp_match in sorted_matches {
            let range = timestamp_match.start_pos..timestamp_match.end_pos;
            if range.end <= result.len() {
                result.replace_range(range, "<TIMESTAMP>");
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_timestamp_indicators_year_and_colon() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 10:00:00"
        ));
    }

    #[test]
    fn has_timestamp_indicators_iso8601() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "foo:barT"
        ));
    }

    #[test]
    fn has_timestamp_indicators_month_name() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jan 1 10:00:00"
        ));
    }

    #[test]
    fn has_timestamp_indicators_k8s_level() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1025 10:00:00.000"
        ));
    }

    #[test]
    fn has_timestamp_indicators_no_colon_rejects() {
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 no colon"
        ));
    }

    #[test]
    fn has_timestamp_indicators_colon_but_no_date() {
        // Has colon but no year, date separator, month name, or k8s indicator
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "foo:bar"
        ));
    }

    #[test]
    fn has_timestamp_indicators_empty() {
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(""));
    }

    #[test]
    fn has_timestamp_indicators_bracket() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "[10:00:00]"
        ));
    }

    // Additional per-condition tests for remaining || branches

    #[test]
    fn ts_ind_year_19() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "1999-01:00"
        ));
    }

    #[test]
    fn ts_ind_dash_only() {
        // Has : and - but no year/T/month/k8s
        assert!(UnifiedTimestampDetector::has_timestamp_indicators("a-b:c"));
    }

    #[test]
    fn ts_ind_feb() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Feb 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_mar() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Mar 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_apr() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Apr 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_may() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "May 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_jun() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jun 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_jul() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jul 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_aug() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Aug 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_sep() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Sep 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_oct() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Oct 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_nov() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Nov 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_dec() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Dec 1 10:00"
        ));
    }

    // K8s level prefixes: W, E, F and other month combinations

    #[test]
    fn ts_ind_w09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1029 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1029 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1029 10:00:00"
        ));
    }

    // ---- resolve_overlaps: boundary tests ----

    fn make_match(start: usize, end: usize, specificity: u32) -> TimestampMatch {
        TimestampMatch {
            original: String::new(),
            start_pos: start,
            end_pos: end,
            priority: super::super::priority::PatternPriority::new(
                specificity,
                super::super::priority::FormatFamily::Structured,
            ),
        }
    }

    #[test]
    fn resolve_overlaps_empty() {
        let result = UnifiedTimestampDetector::resolve_overlaps(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_overlaps_no_overlap() {
        let matches = vec![make_match(0, 10, 90), make_match(15, 25, 80)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn resolve_overlaps_overlap_higher_wins() {
        // Two matches overlap: 0..20 and 10..30
        // Higher specificity (90) should win
        let matches = vec![make_match(0, 20, 90), make_match(10, 30, 50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 0);
        assert_eq!(result[0].end_pos, 20);
    }

    #[test]
    fn resolve_overlaps_adjacent_both_survive() {
        // Touching but not overlapping: 0..10 and 10..20
        let matches = vec![make_match(0, 10, 90), make_match(10, 20, 80)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn resolve_overlaps_end_equals_start_both_survive() {
        // Kills mutant: `candidate_range.end > used_range.start` → `>= `
        // Higher priority match at 5..15 selected first.
        // Then candidate 0..5: start(0) < used_end(15) = true,
        // end(5) > used_start(5) → 5 > 5 = false → no overlap → survives.
        // With >=: 5 >= 5 = true → overlap → wrongly excluded.
        let matches = vec![make_match(5, 15, 90), make_match(0, 5, 50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2, "adjacent end==start should not overlap");
    }

    // ---- Mutant-killing: has_timestamp_indicators line 84 ----

    #[test]
    fn ts_ind_requires_colon() {
        // Kills mutant: `text.contains(':') &&` condition
        // Input with date indicators but NO colon should return false
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 no colon here"
        ));
    }

    #[test]
    fn ts_ind_colon_with_year_20() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "2024:00"
        ));
    }

    // ---- Mutant-killing: resolve_overlaps line 124 ----

    #[test]
    fn resolve_overlaps_single_match() {
        // Single match should always survive
        let matches = vec![make_match(5, 15, 90)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 5);
    }

    #[test]
    fn resolve_overlaps_three_overlapping() {
        // Three overlapping matches: 0..20, 5..25, 10..30
        // Highest priority (90) wins, others excluded
        let matches = vec![
            make_match(0, 20, 90),
            make_match(5, 25, 50),
            make_match(10, 30, 30),
        ];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1, "only highest priority should survive");
        assert_eq!(result[0].start_pos, 0);
    }
}
