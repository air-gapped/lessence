// Central Pattern Registry with Deduplication
// Constitutional requirement: 30+ patterns, thread-safe access

use super::{FormatFamily, PatternPriority, PatternSource, TimestampFormat, TimestampPattern};
use regex::Regex;
use std::collections::HashMap;

/// Central registry for all timestamp patterns with deduplication
pub struct TimestampRegistry {
    patterns: Vec<TimestampPattern>,
}

impl Default for TimestampRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TimestampRegistry {
    /// Initialize registry with patterns from both source implementations
    /// Constitutional requirement: Merge all patterns without loss
    pub fn new() -> Self {
        // Load patterns from both sources
        let timestamp_patterns = Self::load_original_timestamp_patterns();
        let essence_patterns = Self::load_original_essence_patterns();

        // Merge and deduplicate
        let mut merged_patterns =
            Self::merge_duplicate_patterns(timestamp_patterns, essence_patterns);

        // Assign priorities
        Self::assign_pattern_priorities(&mut merged_patterns);

        // Sort by priority (highest first)
        merged_patterns.sort_by(|a, b| {
            a.priority
                .effective_score()
                .cmp(&b.priority.effective_score())
        });

        TimestampRegistry {
            patterns: merged_patterns,
        }
    }

    /// Load patterns from original timestamp.rs implementation
    fn load_original_timestamp_patterns() -> Vec<TimestampPattern> {
        vec![
            // ISO 8601 Enhanced
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)\b").unwrap(),
                format_type: TimestampFormat::ISO8601Enhanced,
                priority: PatternPriority::new(100, FormatFamily::Structured),
                source: PatternSource::OriginalTimestamp,
            },
            // Week date format
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-W\d{2}-\d(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?)?\b").unwrap(),
                format_type: TimestampFormat::WeekDate,
                priority: PatternPriority::new(90, FormatFamily::Structured),
                source: PatternSource::OriginalTimestamp,
            },
            // Ordinal date format
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{3}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?)?\b").unwrap(),
                format_type: TimestampFormat::OrdinalDate,
                priority: PatternPriority::new(90, FormatFamily::Structured),
                source: PatternSource::OriginalTimestamp,
            },
            // Standard datetime
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:\s*(?:UTC|GMT|[+-]\d{2}:?\d{2}?))?\b").unwrap(),
                format_type: TimestampFormat::ISO8601Full,
                priority: PatternPriority::new(85, FormatFamily::Structured),
                source: PatternSource::OriginalTimestamp,
            },
            // Java timestamp with comma
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,9}\b").unwrap(),
                format_type: TimestampFormat::JavaSimpleDate,
                priority: PatternPriority::new(75, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // 12-hour format with AM/PM
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?\s*(?:AM|PM|am|pm)\b").unwrap(),
                format_type: TimestampFormat::USDate,
                priority: PatternPriority::new(70, FormatFamily::Regional),
                source: PatternSource::OriginalTimestamp,
            },
            // MySQL YYMMDD
            TimestampPattern {
                regex: Regex::new(r"\b\d{6}\s+\d{2}:\d{2}:\d{2}\b").unwrap(),
                format_type: TimestampFormat::MySQLTimestamp,
                priority: PatternPriority::new(60, FormatFamily::Database),
                source: PatternSource::OriginalTimestamp,
            },
            // Oracle format
            TimestampPattern {
                regex: Regex::new(r"\b\d{2}-[A-Z]{3}-\d{2}\s+\d{2}\.\d{2}\.\d{2}(?:\.\d+)?\s*(?:AM|PM)?").unwrap(),
                format_type: TimestampFormat::Oracle,
                priority: PatternPriority::new(65, FormatFamily::Database),
                source: PatternSource::OriginalTimestamp,
            },
            // Compact timestamp
            TimestampPattern {
                regex: Regex::new(r"\b20\d{12}\b").unwrap(),
                format_type: TimestampFormat::CompactFormat,
                priority: PatternPriority::new(50, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // Apache/Nginx common log
            TimestampPattern {
                regex: Regex::new(r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]").unwrap(),
                format_type: TimestampFormat::ApacheCommon,
                priority: PatternPriority::new(80, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // Alternative web format
            TimestampPattern {
                regex: Regex::new(r"\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\b").unwrap(),
                format_type: TimestampFormat::NginxAccess,
                priority: PatternPriority::new(75, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // US format MM/DD/YYYY
            TimestampPattern {
                regex: Regex::new(r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:\s*(?:AM|PM))?\b").unwrap(),
                format_type: TimestampFormat::USDate,
                priority: PatternPriority::new(60, FormatFamily::Regional),
                source: PatternSource::OriginalTimestamp,
            },
            // US format MM-DD-YYYY
            TimestampPattern {
                regex: Regex::new(r"\b\d{1,2}-\d{1,2}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::USDateDash,
                priority: PatternPriority::new(60, FormatFamily::Regional),
                source: PatternSource::OriginalTimestamp,
            },
            // European DD/MM/YYYY
            TimestampPattern {
                regex: Regex::new(r"\b[0-3]\d/[01]\d/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::EuropeanDate,
                priority: PatternPriority::new(60, FormatFamily::Regional),
                source: PatternSource::OriginalTimestamp,
            },
            // European DD.MM.YYYY
            TimestampPattern {
                regex: Regex::new(r"\b[0-3]\d\.[01]\d\.\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::EuropeanDateDot,
                priority: PatternPriority::new(60, FormatFamily::Regional),
                source: PatternSource::OriginalTimestamp,
            },
            // Standard syslog
            TimestampPattern {
                regex: Regex::new(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::SyslogBSD,
                priority: PatternPriority::new(55, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // Syslog with year
            TimestampPattern {
                regex: Regex::new(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::SyslogWithYear,
                priority: PatternPriority::new(60, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // Kubernetes/Go log format
            TimestampPattern {
                regex: Regex::new(r"[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+").unwrap(),
                format_type: TimestampFormat::KubernetesLog,
                priority: PatternPriority::new(85, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // Unix timestamp (lowest priority)
            TimestampPattern {
                regex: Regex::new(r"\b1[0-9]{9,10}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::UnixTimestamp,
                priority: PatternPriority::new(10, FormatFamily::Unix),
                source: PatternSource::OriginalTimestamp,
            },
            // Unix with @ prefix
            TimestampPattern {
                regex: Regex::new(r"@1[0-9]{9,10}(?:\.\d{1,9})?\b").unwrap(),
                format_type: TimestampFormat::UnixPrefixed,
                priority: PatternPriority::new(20, FormatFamily::Unix),
                source: PatternSource::OriginalTimestamp,
            },
            // Unix in brackets
            TimestampPattern {
                regex: Regex::new(r"\[1[0-9]{9,10}(?:\.\d{1,9})?\]").unwrap(),
                format_type: TimestampFormat::UnixBracketed,
                priority: PatternPriority::new(25, FormatFamily::Unix),
                source: PatternSource::OriginalTimestamp,
            },
            // Docker/Container logs
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z\b").unwrap(),
                format_type: TimestampFormat::DockerLog,
                priority: PatternPriority::new(95, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // Time only with timezone
            TimestampPattern {
                regex: Regex::new(r"\b\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?\b").unwrap(),
                format_type: TimestampFormat::TimeOnly,
                priority: PatternPriority::new(30, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // ISO 8601 durations
            TimestampPattern {
                regex: Regex::new(r"\bP(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?\b").unwrap(),
                format_type: TimestampFormat::Duration,
                priority: PatternPriority::new(35, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // IBM YY.DDD format
            TimestampPattern {
                regex: Regex::new(r"\b\d{2}\.\d{3}\s+\d{2}:\d{2}:\d{2}\b").unwrap(),
                format_type: TimestampFormat::IBMFormat,
                priority: PatternPriority::new(45, FormatFamily::Legacy),
                source: PatternSource::OriginalTimestamp,
            },
            // RFC 2822 format
            TimestampPattern {
                regex: Regex::new(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b").unwrap(),
                format_type: TimestampFormat::RFC2822,
                priority: PatternPriority::new(85, FormatFamily::Structured),
                source: PatternSource::OriginalTimestamp,
            },
            // Log4j format
            TimestampPattern {
                regex: Regex::new(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+\[").unwrap(),
                format_type: TimestampFormat::Log4j,
                priority: PatternPriority::new(70, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
            // Splunk format
            TimestampPattern {
                regex: Regex::new(r"\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\.\d{1,6}\b").unwrap(),
                format_type: TimestampFormat::Splunk,
                priority: PatternPriority::new(65, FormatFamily::Application),
                source: PatternSource::OriginalTimestamp,
            },
        ]
    }

    /// Load patterns from original essence/processor.rs implementation
    fn load_original_essence_patterns() -> Vec<TimestampPattern> {
        vec![
            // Additional patterns from essence mode that aren't in timestamp.rs
            TimestampPattern {
                regex: Regex::new(r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)")
                    .unwrap(),
                format_type: TimestampFormat::WindowsEvent,
                priority: PatternPriority::new(55, FormatFamily::Regional),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}").unwrap(),
                format_type: TimestampFormat::WindowsIIS,
                priority: PatternPriority::new(50, FormatFamily::Regional),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}").unwrap(),
                format_type: TimestampFormat::GitCommit,
                priority: PatternPriority::new(55, FormatFamily::Legacy),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z").unwrap(),
                format_type: TimestampFormat::Aws,
                priority: PatternPriority::new(85, FormatFamily::Application),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z").unwrap(),
                format_type: TimestampFormat::Gcp,
                priority: PatternPriority::new(85, FormatFamily::Application),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z").unwrap(),
                format_type: TimestampFormat::Azure,
                priority: PatternPriority::new(85, FormatFamily::Application),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}").unwrap(),
                format_type: TimestampFormat::Ansic,
                priority: PatternPriority::new(50, FormatFamily::Legacy),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\w{3},\s+\d{2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT")
                    .unwrap(),
                format_type: TimestampFormat::RFC822,
                priority: PatternPriority::new(80, FormatFamily::Structured),
                source: PatternSource::OriginalEssence,
            },
            // Unix timestamp variants from essence
            TimestampPattern {
                regex: Regex::new(r"\b\d{13}\b").unwrap(),
                format_type: TimestampFormat::UnixTimestampMs,
                priority: PatternPriority::new(15, FormatFamily::Unix),
                source: PatternSource::OriginalEssence,
            },
            TimestampPattern {
                regex: Regex::new(r"\b\d{19}\b").unwrap(),
                format_type: TimestampFormat::UnixTimestampNs,
                priority: PatternPriority::new(18, FormatFamily::Unix),
                source: PatternSource::OriginalEssence,
            },
        ]
    }

    /// Merge duplicate patterns into comprehensive versions
    fn merge_duplicate_patterns(
        timestamp_patterns: Vec<TimestampPattern>,
        essence_patterns: Vec<TimestampPattern>,
    ) -> Vec<TimestampPattern> {
        let mut merged_patterns = Vec::new();

        // Start with timestamp patterns as base
        let mut pattern_map: HashMap<String, TimestampPattern> = HashMap::new();

        // Add all timestamp patterns first
        for pattern in timestamp_patterns {
            let key = pattern.regex.as_str().to_string();
            pattern_map.insert(key, pattern);
        }

        // Check essence patterns for duplicates and merge
        for essence_pattern in essence_patterns {
            let key = essence_pattern.regex.as_str().to_string();

            match pattern_map.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    // Duplicate found - mark as merged
                    entry.get_mut().source = PatternSource::Merged;
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    // Unique pattern from essence mode
                    entry.insert(essence_pattern);
                }
            }
        }

        // Convert to vector
        merged_patterns.extend(pattern_map.into_values());

        merged_patterns
    }

    /// Assign priority ordering to prevent conflicts
    fn assign_pattern_priorities(patterns: &mut [TimestampPattern]) {
        for pattern in patterns.iter_mut() {
            let specificity = pattern.format_type.specificity_score();
            let family = pattern.format_type.format_family();
            pattern.priority = PatternPriority::new(specificity, family);
        }
    }

    /// Get all patterns for detection operations
    pub fn get_patterns(&self) -> &[TimestampPattern] {
        &self.patterns
    }
}
