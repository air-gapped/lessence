// Pattern Priority System for Overlap Resolution
// Constitutional requirement: Unix timestamps lowest priority

/// Pattern priority for conflict resolution
/// Ensures longest/most specific matches win over shorter/generic ones
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternPriority {
    pub specificity_score: u32,
    pub format_family: FormatFamily,
    pub unix_timestamp_penalty: bool,
}

impl PatternPriority {
    /// Create new priority with automatic unix timestamp penalty
    pub fn new(specificity_score: u32, format_family: FormatFamily) -> Self {
        let unix_timestamp_penalty = matches!(format_family, FormatFamily::Unix);

        Self {
            specificity_score,
            format_family,
            unix_timestamp_penalty,
        }
    }

    /// Calculate effective priority score for ordering
    /// Lower scores = higher priority (processed first)
    pub fn effective_score(&self) -> i32 {
        // specificity_score is always a small non-negative value (pattern count), safe to convert
        let base_score = -i32::try_from(self.specificity_score).unwrap_or(0); // Negative for reverse order

        // Apply family modifiers
        let family_modifier = match self.format_family {
            FormatFamily::Structured => 0, // Highest priority
            FormatFamily::Application => 100,
            FormatFamily::Regional => 200,
            FormatFamily::Database => 300,
            FormatFamily::Legacy => 400,
            FormatFamily::Unix => 1000, // Lowest priority
        };

        // Unix timestamp penalty (even lower priority)
        let penalty = if self.unix_timestamp_penalty { 500 } else { 0 };

        base_score + family_modifier + penalty
    }
}

/// Format family for priority band assignment
/// Constitutional requirement: Unix timestamps must be lowest priority
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FormatFamily {
    Structured,  // ISO8601, RFC formats (highest priority)
    Application, // Java, Docker, web server formats
    Regional,    // US, European date formats
    Database,    // MySQL, PostgreSQL, Oracle formats
    Legacy,      // Syslog, IBM, compact formats
    Unix,        // Numeric timestamps (lowest priority)
}
