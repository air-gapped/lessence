pub use crate::patterns::Token;

pub use detector::{Band, TimestampPattern, UnifiedTimestampDetector, patterns};

pub mod detector;

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub normalized_text: String,
    pub matches: Vec<TimestampMatch>,
}

#[derive(Debug, Clone)]
pub struct TimestampMatch {
    pub original: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub score: i32,
    pub pattern_index: usize,
}

impl TimestampMatch {
    pub fn precedence(&self) -> (i32, usize, usize) {
        (self.score, self.start_pos, self.pattern_index)
    }
}
