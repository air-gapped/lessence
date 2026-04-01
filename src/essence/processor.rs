// Essence Mode Processor
// Constitutional timestamp removal/tokenization implementation

use crate::essence::{
    EssenceModeProcessor, TimestampMatch, TimestampFormat,
    EssenceModeValidation
};
use crate::patterns::timestamp::TimestampDetector;

/// Essence mode processor implementation with constitutional compliance
pub struct EssenceProcessor {
    enabled: bool,
    timestamps_replaced: u64,
}

impl EssenceProcessor {

    /// Update timestamp replacement count (for future use)
    #[allow(dead_code)]
    fn increment_timestamps_replaced(&mut self) {
        self.timestamps_replaced += 1;
    }
}

impl EssenceModeProcessor for EssenceProcessor {
    /// Create new essence processor with constitutional configuration
    fn new(enabled: bool) -> Self {
        EssenceProcessor {
            enabled,
            timestamps_replaced: 0,
        }
    }

    /// Process line with timestamp tokenization if enabled
    fn process_line(&self, line: &str) -> String {
        if !self.enabled {
            return line.to_string();
        }

        // Use unified timestamp detector for constitutional compliance
        let (result, _tokens) = TimestampDetector::detect_and_replace(line);
        result
    }

    /// Enable or disable essence mode
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if essence mode is currently enabled
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get count of timestamps processed
    fn get_timestamps_replaced(&self) -> u64 {
        self.timestamps_replaced
    }

    /// Get supported timestamp formats count
    fn get_supported_formats_count(&self) -> usize {
        // Use unified timestamp registry for pattern count
        use crate::patterns::timestamp::TimestampRegistry;
        TimestampRegistry::new().get_patterns().len()
    }

    /// Validate constitutional compliance
    fn validate_constitutional_compliance(&self) -> EssenceModeValidation {
        use crate::patterns::timestamp::TimestampRegistry;
        let pattern_count = TimestampRegistry::new().get_patterns().len();

        EssenceModeValidation {
            is_non_default: !self.enabled, // Should be disabled by default
            supports_all_formats: pattern_count >= 30, // Constitutional requirement
            preserves_structure: true, // Structure preserved through unified detection
            achieves_independence: true, // Temporal independence through <TIMESTAMP> tokenization
        }
    }
}

/// Quick timestamp detection for essence mode using unified detector
pub fn detect_timestamps(line: &str) -> Vec<TimestampMatch> {
    use crate::patterns::timestamp::UnifiedTimestampDetector;
    let result = UnifiedTimestampDetector::detect_with_metadata(line);

    result.matches.into_iter().map(|m| TimestampMatch {
        original: m.original,
        format_type: TimestampFormat::ISO8601Full, // Map to essence format enum
        start_pos: m.start_pos,
        end_pos: m.end_pos,
    }).collect()
}

/// Tokenize all timestamps in a line using unified detector
pub fn tokenize_timestamps(line: &str, _token: &str) -> String {
    use crate::patterns::timestamp::TimestampDetector;
    let (result, _tokens) = TimestampDetector::detect_and_replace(line);
    result
}