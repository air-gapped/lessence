// Essence Mode Module
// Constitutional timestamp removal/tokenization for temporal independence

pub mod processor;

/// Essence mode processor trait for constitutional compliance
pub trait EssenceModeProcessor {
    /// Create new essence processor with constitutional configuration
    fn new(enabled: bool) -> Self;

    /// Process line with timestamp tokenization if enabled
    fn process_line(&self, line: &str) -> String;

    /// Enable or disable essence mode
    fn set_enabled(&mut self, enabled: bool);

    /// Check if essence mode is currently enabled
    fn is_enabled(&self) -> bool;

    /// Get count of timestamps processed
    fn get_timestamps_replaced(&self) -> u64;

    /// Get supported timestamp formats count
    fn get_supported_formats_count(&self) -> usize;

    /// Validate constitutional compliance
    fn validate_constitutional_compliance(&self) -> EssenceModeValidation;
}

/// Validation result for essence mode constitutional compliance
#[derive(Debug, Clone)]
pub struct EssenceModeValidation {
    pub is_non_default: bool,           // Must be disabled by default
    pub supports_all_formats: bool,     // Must support ALL timestamp formats
    pub preserves_structure: bool,      // Must preserve log structure
    pub achieves_independence: bool,    // Must achieve temporal independence
}

impl EssenceModeValidation {
    /// Check if essence mode meets all constitutional requirements
    pub fn meets_constitutional_requirements(&self) -> bool {
        self.is_non_default
            && self.supports_all_formats
            && self.preserves_structure
            && self.achieves_independence
    }
}

/// Tokenization strategy for timestamp replacement
#[derive(Debug, Clone)]
pub enum TokenizationStrategy {
    ReplaceWithToken(String), // "<TIMESTAMP>"
    RemoveCompletely,
    NormalizeFormat(String),
}

impl Default for TokenizationStrategy {
    fn default() -> Self {
        TokenizationStrategy::ReplaceWithToken("<TIMESTAMP>".to_string())
    }
}

/// Timestamp format detection result
#[derive(Debug, Clone)]
pub struct TimestampMatch {
    pub original: String,
    pub format_type: TimestampFormat,
    pub start_pos: usize,
    pub end_pos: usize,
}

/// Supported timestamp formats for constitutional compliance
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TimestampFormat {
    // ISO 8601 variants
    ISO8601Full,        // 2025-09-28T10:15:00Z
    ISO8601NoZ,         // 2025-09-28T10:15:00
    ISO8601Date,        // 2025-09-28
    ISO8601Time,        // 10:15:00

    // RFC 3339 variants
    RFC3339,            // 2025-09-28T10:15:00.123Z
    RFC3339NoZ,         // 2025-09-28T10:15:00.123

    // Syslog formats
    SyslogBSD,          // Sep 28 10:15:00
    SyslogRFC5424,      // 2025-09-28T10:15:00.123456Z

    // Apache/Nginx formats
    ApacheCommon,       // [28/Sep/2025:10:15:00 +0000]
    ApacheError,        // [Sun Sep 28 10:15:00.123456 2025]
    NginxAccess,        // 28/Sep/2025:10:15:00 +0000

    // Application-specific formats
    JavaSimpleDate,     // Sep 28, 2025 10:15:00 AM
    KubernetesLog,      // 2025-09-28T10:15:00.123456789Z
    ElasticsearchLog,   // 2025-09-28 10:15:00,123
    DockerLog,          // 2025-09-28T10:15:00.123456789Z

    // Unix timestamps
    UnixTimestamp,      // 1727515000
    UnixTimestampMs,    // 1727515000123
    UnixTimestampNs,    // 1727515000123456789

    // Database formats
    MySQLTimestamp,     // 2025-09-28 10:15:00
    PostgreSQLTimestamp, // 2025-09-28 10:15:00.123456

    // Windows formats
    WindowsEvent,       // 9/28/2025 10:15:00 AM
    WindowsIIS,         // 2025-09-28 10:15:00

    // Custom application formats
    GitCommit,          // Sep 28 10:15:00 2025
    Aws,                // 2025-09-28T10:15:00.000Z
    Gcp,                // 2025-09-28T10:15:00.123456Z
    Azure,              // 2025-09-28T10:15:00.1234567Z

    // Relative time formats
    RelativeTime,       // "2 hours ago", "yesterday"
    Duration,           // "1h2m3s", "5 minutes"

    // Other common formats
    CFormat,            // Sep 28 10:15:00
    RFC822,             // Sun, 28 Sep 2025 10:15:00 GMT
    RFC850,             // Sunday, 28-Sep-25 10:15:00 GMT
    Ansic,              // Sun Sep 28 10:15:00 2025
}

/// Essence mode error types
#[derive(Debug, Clone)]
pub enum EssenceModeError {
    InvalidConfiguration(String),
    PatternCompilationError(String),
    ProcessingError(String),
    ConstitutionalViolation(String),
}

impl std::fmt::Display for EssenceModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EssenceModeError::InvalidConfiguration(msg) => {
                write!(f, "Invalid essence mode configuration: {}", msg)
            }
            EssenceModeError::PatternCompilationError(msg) => {
                write!(f, "Pattern compilation error: {}", msg)
            }
            EssenceModeError::ProcessingError(msg) => {
                write!(f, "Processing error: {}", msg)
            }
            EssenceModeError::ConstitutionalViolation(msg) => {
                write!(f, "Constitutional violation in essence mode: {}", msg)
            }
        }
    }
}

impl std::error::Error for EssenceModeError {}