// Unified Timestamp Detection Module
// Constitutional compliance: All 30+ timestamp formats centralized

// Removed unused imports - functionality moved to submodules

pub use crate::patterns::Token;

// Re-export unified interfaces
pub use detector::UnifiedTimestampDetector;
pub use registry::TimestampRegistry;
pub use formats::{TimestampPattern, TimestampFormat, PatternSource};
pub use priority::{PatternPriority, FormatFamily};

// Compatibility layer for old API
pub struct TimestampDetector;

impl TimestampDetector {
    /// Legacy API compatibility - delegates to UnifiedTimestampDetector
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        UnifiedTimestampDetector::detect_and_replace(text)
    }
}

// Module structure
pub mod detector;
pub mod registry;
pub mod formats;
pub mod priority;

/// Detection result with comprehensive metadata
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub normalized_text: String,
    pub matches: Vec<TimestampMatch>,
}

/// Individual timestamp match with position and metadata
#[derive(Debug, Clone)]
pub struct TimestampMatch {
    pub original: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub priority: PatternPriority,
}

// Implementation will be in detector.rs as per contracts