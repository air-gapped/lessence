// Timestamp Format Definitions and Pattern Structures
// Constitutional requirement: All 30+ timestamp formats without shortcuts

use regex::Regex;
use super::{PatternPriority, FormatFamily};

/// Individual timestamp pattern with metadata
#[derive(Debug, Clone)]
pub struct TimestampPattern {
    pub regex: Regex,
    pub format_type: TimestampFormat,
    pub priority: PatternPriority,
    pub source: PatternSource,
}

/// Comprehensive timestamp format classification
/// Constitutional requirement: Support ALL formats from both implementations
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum TimestampFormat {
    // ISO8601 family
    ISO8601Full,
    ISO8601NoZ,
    ISO8601Date,
    ISO8601Time,
    ISO8601Enhanced,
    WeekDate,
    OrdinalDate,

    // RFC family
    RFC3339,
    RFC3339NoZ,
    RFC2822,

    // Application family
    JavaSimpleDate,
    KubernetesLog,
    DockerLog,
    ElasticsearchLog,
    Log4j,
    Splunk,

    // Database family
    MySQLTimestamp,
    PostgreSQLTimestamp,
    Oracle,

    // Regional family
    USDate,
    USDateDash,
    EuropeanDate,
    EuropeanDateDot,

    // Web server family
    ApacheCommon,
    ApacheError,
    NginxAccess,

    // Unix family
    UnixTimestamp,
    UnixTimestampMs,
    UnixTimestampNs,
    UnixBracketed,
    UnixPrefixed,

    // Legacy family
    SyslogBSD,
    SyslogRFC5424,
    SyslogWithYear,
    IBMFormat,
    CompactFormat,

    // Time-only
    TimeOnly,

    // Duration
    Duration,

    // Additional formats found in essence/processor.rs
    WindowsEvent,
    WindowsIIS,
    GitCommit,
    AWS,
    GCP,
    Azure,
    ANSIC,
    RFC822,
}

impl TimestampFormat {
    /// Get format family for priority assignment
    pub fn format_family(&self) -> FormatFamily {
        match self {
            TimestampFormat::ISO8601Full
            | TimestampFormat::ISO8601NoZ
            | TimestampFormat::ISO8601Date
            | TimestampFormat::ISO8601Time
            | TimestampFormat::ISO8601Enhanced
            | TimestampFormat::WeekDate
            | TimestampFormat::OrdinalDate
            | TimestampFormat::RFC3339
            | TimestampFormat::RFC3339NoZ
            | TimestampFormat::RFC2822
            | TimestampFormat::RFC822 => FormatFamily::Structured,

            TimestampFormat::JavaSimpleDate
            | TimestampFormat::KubernetesLog
            | TimestampFormat::DockerLog
            | TimestampFormat::ElasticsearchLog
            | TimestampFormat::Log4j
            | TimestampFormat::Splunk
            | TimestampFormat::ApacheCommon
            | TimestampFormat::ApacheError
            | TimestampFormat::NginxAccess
            | TimestampFormat::AWS
            | TimestampFormat::GCP
            | TimestampFormat::Azure => FormatFamily::Application,

            TimestampFormat::USDate
            | TimestampFormat::USDateDash
            | TimestampFormat::EuropeanDate
            | TimestampFormat::EuropeanDateDot
            | TimestampFormat::WindowsEvent
            | TimestampFormat::WindowsIIS => FormatFamily::Regional,

            TimestampFormat::MySQLTimestamp
            | TimestampFormat::PostgreSQLTimestamp
            | TimestampFormat::Oracle => FormatFamily::Database,

            TimestampFormat::SyslogBSD
            | TimestampFormat::SyslogRFC5424
            | TimestampFormat::SyslogWithYear
            | TimestampFormat::IBMFormat
            | TimestampFormat::CompactFormat
            | TimestampFormat::GitCommit
            | TimestampFormat::ANSIC => FormatFamily::Legacy,

            TimestampFormat::UnixTimestamp
            | TimestampFormat::UnixTimestampMs
            | TimestampFormat::UnixTimestampNs
            | TimestampFormat::UnixBracketed
            | TimestampFormat::UnixPrefixed => FormatFamily::Unix,

            TimestampFormat::TimeOnly
            | TimestampFormat::Duration => FormatFamily::Legacy,
        }
    }

    /// Calculate specificity score for priority ordering
    pub fn specificity_score(&self) -> u32 {
        match self {
            // Most specific: Full ISO dates with timezone and nanoseconds
            TimestampFormat::ISO8601Enhanced
            | TimestampFormat::KubernetesLog
            | TimestampFormat::DockerLog => 100,

            // High specificity: Structured formats with timezone
            TimestampFormat::ISO8601Full
            | TimestampFormat::RFC3339
            | TimestampFormat::WeekDate
            | TimestampFormat::OrdinalDate => 90,

            // Medium-high: Structured without timezone
            TimestampFormat::ISO8601NoZ
            | TimestampFormat::RFC3339NoZ
            | TimestampFormat::RFC2822 => 80,

            // Medium: Application-specific formats
            TimestampFormat::ApacheCommon
            | TimestampFormat::ApacheError
            | TimestampFormat::JavaSimpleDate
            | TimestampFormat::Log4j
            | TimestampFormat::ElasticsearchLog => 70,

            // Medium-low: Regional and database formats
            TimestampFormat::USDate
            | TimestampFormat::EuropeanDate
            | TimestampFormat::MySQLTimestamp
            | TimestampFormat::PostgreSQLTimestamp
            | TimestampFormat::Oracle => 60,

            // Low: Legacy and simple formats
            TimestampFormat::SyslogBSD
            | TimestampFormat::SyslogRFC5424
            | TimestampFormat::CompactFormat
            | TimestampFormat::IBMFormat => 50,

            // Very low: Unix timestamps (high false positive risk)
            TimestampFormat::UnixTimestamp
            | TimestampFormat::UnixTimestampMs
            | TimestampFormat::UnixTimestampNs => 10,

            // Lowest: Prefixed unix (more specific but still risky)
            TimestampFormat::UnixBracketed
            | TimestampFormat::UnixPrefixed => 20,

            // Default for remaining formats
            _ => 40,
        }
    }
}

/// Pattern source tracking for maintenance and debugging
#[derive(Debug, Clone, PartialEq)]
pub enum PatternSource {
    OriginalTimestamp,
    OriginalEssence,
    Merged,
}