//! Unified timestamp detection.
//!
//! The whole engine is one table of regexes in [`detector`]; see that module's
//! docs for the scoring bands and how to add a format.

pub use crate::patterns::Token;

pub use detector::{TimestampPattern, UnifiedTimestampDetector, patterns};

pub mod detector;

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
    /// Overlap-resolution score copied from the matching pattern; lower wins.
    pub score: i32,
}
