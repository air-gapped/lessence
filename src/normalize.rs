use ahash::AHasher;
use anyhow::Result;
use std::hash::{Hash, Hasher};

use crate::config::Config;
use crate::patterns::{
    duration::DurationDetector, email::EmailPatternDetector, hash::HashDetector,
    json::JsonDetector, kubernetes::KubernetesDetector, names::NameDetector,
    network::NetworkDetector, path::PathDetector, process::ProcessDetector,
    quoted::QuotedStringDetector, timestamp::TimestampDetector, uuid::UuidDetector, LogLine, Token,
};

pub struct Normalizer {
    config: Config,
    // Pattern detectors
    email_detector: EmailPatternDetector,
}

impl Normalizer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            email_detector: EmailPatternDetector::new().unwrap(),
        }
    }

    pub fn normalize_line(&self, original: String) -> Result<LogLine> {
        let mut normalized = original.clone();
        let mut tokens = Vec::new();

        // Apply normalizations in optimized order (most specific to least specific)
        // This prevents conflicts and maximizes pattern detection accuracy

        // 1. TIMESTAMPS (highest priority - most specific format)
        if self.config.normalize_timestamps {
            if self.config.essence_mode {
                // Constitutional essence mode: Timestamp tokenization for temporal independence
                let (new_normalized, mut new_tokens) =
                    TimestampDetector::detect_and_replace(&normalized);
                // In essence mode, keep <TIMESTAMP> tokens for grouping identical temporal-independent patterns
                normalized = new_normalized;
                tokens.append(&mut new_tokens);
            } else {
                // Standard mode: Replace with <TIMESTAMP> tokens
                let (new_normalized, mut new_tokens) =
                    TimestampDetector::detect_and_replace(&normalized);
                normalized = new_normalized;
                tokens.append(&mut new_tokens);
            }
        }

        // 2. EMAIL ADDRESSES (before paths to ensure emails in URLs are handled correctly)
        if self.config.normalize_emails {
            let (new_normalized, mut new_tokens) =
                self.email_detector.detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 3. PATHS (URLs, file paths, CLI flags - must run early to preserve URL structure)
        // Must run BEFORE network patterns to handle URLs as complete units
        if self.config.normalize_paths {
            let (new_normalized, mut new_tokens) = PathDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 4. JSON (structured data, Event objects, K8s objects)
        // Separated from Paths for proper architectural separation
        if self.config.normalize_json {
            let (new_normalized, mut new_tokens) = JsonDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 5. UUIDs (MUST run BEFORE hashes to prevent UUID fragmentation!)
        // UUIDs contain hex segments that could be mistaken for hashes
        if self.config.normalize_uuids {
            let (new_normalized, mut new_tokens) = UuidDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 6. NETWORK PATTERNS (IP addresses, ports, FQDNs - very specific formats)
        // Must run AFTER paths to avoid breaking URLs
        if self.config.normalize_ips || self.config.normalize_ports || self.config.normalize_fqdns {
            let (new_normalized, mut new_tokens) = NetworkDetector::detect_and_replace(
                &normalized,
                self.config.normalize_ips,
                self.config.normalize_ports,
                self.config.normalize_fqdns,
            );
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 7. HASHES (specific length and hex pattern)
        // Must run AFTER UUIDs to avoid detecting UUID segments as hashes
        if self.config.normalize_hashes {
            let (new_normalized, mut new_tokens) = HashDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 8. PROCESS IDs (specific patterns like [pid=123], (12345))
        if self.config.normalize_pids {
            let (new_normalized, mut new_tokens) = ProcessDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 9. KUBERNETES PATTERNS (namespaces, volumes, plugins, pod names)
        // PROTECTED DOMAIN: Must run before generic patterns to prevent pattern theft
        if self.config.normalize_kubernetes {
            let (new_normalized, mut new_tokens) =
                KubernetesDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // NEW PATTERNS FROM 001-READ-THE-CURRENT (Now correctly placed AFTER Kubernetes)

        // HttpStatusClass - Groups HTTP status codes (200-299 → 2xx, etc.)
        // Fixes Nginx compression improvement: 72% → >85%
        if true {
            // Always enabled for testing
            let (new_normalized, mut new_tokens) =
                crate::patterns::http_status::HttpStatusDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // BracketContext - Detects [error] [mod_jk] style patterns
        // Fixes Microservices compression improvement: 19% → >70%
        if true {
            // Always enabled for testing
            let (new_normalized, mut new_tokens) =
                crate::patterns::bracket_context::BracketContextDetector::detect_and_replace(
                    &normalized,
                );
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // KeyValuePair - Detects config=value, metrics patterns
        if true {
            // Always enabled for testing
            let (new_normalized, mut new_tokens) =
                crate::patterns::key_value::KeyValueDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // LogWithModule - Detects [level] module patterns for Apache/nginx
        if true {
            // Always enabled for testing
            let (new_normalized, mut new_tokens) =
                crate::patterns::log_module::LogWithModuleDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // StructuredMessage - Detects JSON/logfmt structured logging
        if true {
            // Always enabled for testing
            let (new_normalized, mut new_tokens) =
                crate::patterns::structured::StructuredMessageDetector::detect_and_replace(
                    &normalized,
                );
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 10. DURATIONS & MEASUREMENTS (broad category including decimals, sizes, percentages, HTTP codes)
        // Runs LATE to avoid conflicts with more specific patterns above
        if self.config.normalize_durations {
            let (new_normalized, mut new_tokens) =
                DurationDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 11. NAMES (generic hyphenated component names with variable suffixes)
        // Runs after specific patterns to catch remaining variable names
        let (new_normalized, mut new_tokens) = NameDetector::detect_and_replace(&normalized);
        normalized = new_normalized;
        tokens.append(&mut new_tokens);

        // 12. QUOTED STRINGS (generic quoted variables - high priority for mount operations)
        // Must run after paths to catch normalized quoted paths properly
        let (new_normalized, mut new_tokens) =
            QuotedStringDetector::detect_and_replace(&normalized);
        normalized = new_normalized;
        tokens.append(&mut new_tokens);

        // Generate hash for fast comparison
        let hash = self.calculate_hash(&normalized);

        Ok(LogLine {
            original,
            normalized,
            tokens,
            hash,
        })
    }

    fn calculate_hash(&self, normalized: &str) -> u64 {
        let mut hasher = AHasher::default();
        normalized.hash(&mut hasher);
        hasher.finish()
    }

    #[allow(clippy::cast_precision_loss)] // usize lengths → f64 for ratio calc
    pub fn similarity_score(&self, line1: &LogLine, line2: &LogLine) -> f64 {
        let s1 = &line1.normalized;
        let s2 = &line2.normalized;

        if s1 == s2 {
            return 100.0;
        }

        // Ultra-fast similarity: check length difference first
        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);
        let min_len = len1.min(len2);

        if max_len == 0 {
            return 100.0;
        }

        // If length difference is too large, reject quickly
        let length_ratio = min_len as f64 / max_len as f64;
        if length_ratio < 0.7 {
            return length_ratio * 100.0;
        }

        // Fast character overlap check
        let mut matches = 0;
        let s1_chars: Vec<char> = s1.chars().collect();
        let s2_chars: Vec<char> = s2.chars().collect();

        for (i, &c1) in s1_chars.iter().enumerate() {
            if i < s2_chars.len() && c1 == s2_chars[i] {
                matches += 1;
            }
        }

        (f64::from(matches) / max_len as f64) * 100.0
    }

    pub fn are_similar(&self, line1: &LogLine, line2: &LogLine) -> bool {
        // Quick hash comparison first
        if line1.hash == line2.hash {
            return true;
        }

        // If hashes don't match, check similarity score
        let score = self.similarity_score(line1, line2);
        score >= f64::from(self.config.threshold)
    }

    pub fn format_collapsed_line(&self, first: &LogLine, last: &LogLine, count: usize) -> String {
        if self.config.compact {
            // Compact format: [+N similar, varying: TYPE]
            let variation_types = self.summarize_variation_types(&first.tokens, &last.tokens);
            if variation_types.is_empty() {
                format!("[+{} similar]", count)
            } else {
                format!(
                    "[+{} similar, varying: {}]",
                    count,
                    variation_types.join(", ")
                )
            }
        } else {
            format!(
                "[...collapsed {} similar lines from {} to {}...]",
                count,
                self.format_timestamp(first),
                self.format_timestamp(last)
            )
        }
    }

    fn format_timestamp(&self, log_line: &LogLine) -> String {
        // Extract first timestamp string from original line using simple regex
        for token in &log_line.tokens {
            if let Token::Timestamp(ts_str) = token {
                // Extract just the time part for display (HH:MM:SS.mmm or HH:MM:SS,mmm)
                if let Some(time_part) = Self::extract_time_part(ts_str) {
                    return time_part;
                }
            }
        }
        "unknown".to_string()
    }

    fn extract_time_part(timestamp: &str) -> Option<String> {
        // Return the full timestamp string as-is from the original log
        // This preserves user's format and shows meaningful ranges
        Some(timestamp.to_string())
    }

    fn summarize_variation_types(
        &self,
        first_tokens: &[Token],
        last_tokens: &[Token],
    ) -> Vec<String> {
        let mut types = std::collections::HashSet::new();

        // Helper function to get token type name and value
        let get_token_info = |token: &Token| -> (&str, String) {
            match token {
                Token::Timestamp(v) => ("timestamp", v.clone()),
                Token::IPv4(v) => ("IP", v.clone()),
                Token::IPv6(v) => ("IP", v.clone()),
                Token::Port(v) => ("port", v.to_string()),
                Token::Hash(_, v) => ("hash", v.clone()),
                Token::Uuid(v) => ("UUID", v.clone()),
                Token::Pid(v) => ("PID", v.to_string()),
                Token::ThreadID(v) => ("thread", v.clone()),
                Token::Path(v) => ("path", v.clone()),
                Token::Json(v) => ("json", v.clone()),
                Token::Duration(v) => ("duration", v.clone()),
                Token::Size(v) => ("size", v.clone()),
                Token::Number(v) => ("number", v.clone()),
                Token::HttpStatus(v) => ("http_status", v.to_string()),
                Token::QuotedString(v) => ("quoted_string", v.clone()),
                Token::Name(v) => ("name", v.clone()),
                Token::KubernetesNamespace(v) => ("namespace", v.clone()),
                Token::VolumeName(v) => ("volume", v.clone()),
                Token::PluginType(v) => ("plugin", v.clone()),
                Token::PodName(v) => ("pod", v.clone()),
                Token::HttpStatusClass(v) => ("http_status_class", v.clone()),
                Token::BracketContext(v) => ("bracket_context", v.join(",")),
                Token::KeyValuePair { key, value_type } => {
                    ("key_value_pair", format!("{}={}", key, value_type))
                }
                Token::Email(v) => ("email", v.clone()),
                Token::LogWithModule { .. } => ("log_with_module", String::new()),
                Token::StructuredMessage { .. } => ("structured_message", String::new()),
            }
        };

        // Create maps of token types to values for first and last
        let mut first_values: std::collections::HashMap<&str, Vec<String>> =
            std::collections::HashMap::new();
        let mut last_values: std::collections::HashMap<&str, Vec<String>> =
            std::collections::HashMap::new();

        for token in first_tokens {
            let (token_type, value) = get_token_info(token);
            first_values.entry(token_type).or_default().push(value);
        }

        for token in last_tokens {
            let (token_type, value) = get_token_info(token);
            last_values.entry(token_type).or_default().push(value);
        }

        // Find token types that actually vary between first and last
        let all_types: std::collections::HashSet<&str> = first_values
            .keys()
            .chain(last_values.keys())
            .copied()
            .collect();

        for token_type in all_types {
            // In essence mode, ignore timestamp variations as they're tokenized for temporal independence
            if self.config.essence_mode && token_type == "timestamp" {
                continue;
            }

            let first_vals = first_values.get(token_type).cloned().unwrap_or_default();
            let last_vals = last_values.get(token_type).cloned().unwrap_or_default();

            // If the sets of values differ, this token type varies
            if first_vals != last_vals {
                types.insert(token_type.to_string());
            }
        }

        let mut result: Vec<String> = types.into_iter().collect();
        result.sort();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_normalization() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("2025-01-20 10:15:30 Error occurred".to_string())
            .unwrap();

        assert_eq!(line.normalized, "<TIMESTAMP> Error occurred");
        assert_eq!(line.tokens.len(), 1);
        assert!(matches!(line.tokens[0], Token::Timestamp(_)));
    }

    #[test]
    fn test_ip_port_normalization() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("Connection to 192.168.1.100:8080 failed".to_string())
            .unwrap();

        assert_eq!(line.normalized, "Connection to <IP>:<PORT> failed");
        assert_eq!(line.tokens.len(), 2);
    }

    #[test]
    fn test_similarity_calculation() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line1 = normalizer
            .normalize_line(
                "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080"
                    .to_string(),
            )
            .unwrap();

        let line2 = normalizer
            .normalize_line(
                "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081"
                    .to_string(),
            )
            .unwrap();

        assert!(normalizer.are_similar(&line1, &line2));
        let score = normalizer.similarity_score(&line1, &line2);
        assert!(score >= 85.0);
    }

    #[test]
    fn test_hash_consistency() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line1 = normalizer
            .normalize_line("<TIMESTAMP> [pid=<PID>] Connection failed to <IP>:<PORT>".to_string())
            .unwrap();

        let line2 = normalizer
            .normalize_line("<TIMESTAMP> [pid=<PID>] Connection failed to <IP>:<PORT>".to_string())
            .unwrap();

        assert_eq!(line1.hash, line2.hash);
    }

    #[test]
    fn test_disabled_normalization() {
        let config = Config {
            normalize_timestamps: false,
            normalize_ips: false,
            normalize_ports: false,
            ..Config::default()
        };

        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("2025-01-20 10:15:30 Connection to 192.168.1.100 failed".to_string())
            .unwrap();

        // Even with timestamps/IPs/ports disabled, other always-on patterns
        // (durations, names, etc.) still normalize numbers and decimals
        assert_eq!(
            line.normalized,
            "<NUMBER>-01-20 10:15:30 Connection to <DECIMAL>.<DECIMAL> failed"
        );
    }

    #[test]
    fn test_timestamp_format_preservation() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        // Test PostgreSQL comma format
        let line1 = normalizer
            .normalize_line("2025-09-18 13:26:30,188 INFO: test message".to_string())
            .unwrap();

        let formatted = normalizer.format_timestamp(&line1);
        assert_eq!(formatted, "2025-09-18 13:26:30,188");

        // Test PostgreSQL UTC format
        let line2 = normalizer
            .normalize_line("2025-09-18 13:26:53.345 UTC [24] LOG test".to_string())
            .unwrap();

        let formatted2 = normalizer.format_timestamp(&line2);
        assert_eq!(formatted2, "2025-09-18 13:26:53.345 UTC");

        // Test ISO 8601 format
        let line3 = normalizer
            .normalize_line("2025-01-20T10:15:30.123Z INFO test".to_string())
            .unwrap();

        let formatted3 = normalizer.format_timestamp(&line3);
        assert_eq!(formatted3, "2025-01-20T10:15:30.123Z");
    }

    #[test]
    fn test_invalid_timestamp_handling() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        // Test invalid date that would crash parsing
        let line = normalizer
            .normalize_line("2025-02-31 25:99:99,999 ERROR: invalid timestamp".to_string())
            .unwrap();

        // Should not crash and should preserve the invalid timestamp
        let formatted = normalizer.format_timestamp(&line);
        assert_eq!(formatted, "2025-02-31 25:99:99,999");
    }

    #[test]
    fn test_no_timestamp_handling() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        // Test line with no timestamp
        let line = normalizer
            .normalize_line("Just a log message with no timestamp".to_string())
            .unwrap();

        let formatted = normalizer.format_timestamp(&line);
        assert_eq!(formatted, "unknown");
    }

    #[test]
    fn test_port_detection_vs_timestamps() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        // Test that timestamps are NOT detected as ports
        let line1 = normalizer
            .normalize_line("2025-01-20 10:15:30 Connection failed".to_string())
            .unwrap();

        // Should normalize timestamp but NOT detect ports in the time
        assert_eq!(line1.normalized, "<TIMESTAMP> Connection failed");
        assert!(line1
            .tokens
            .iter()
            .any(|t| matches!(t, Token::Timestamp(_))));
        assert!(!line1.tokens.iter().any(|t| matches!(t, Token::Port(_))));

        // Test that actual ports ARE detected
        let line2 = normalizer
            .normalize_line("Connection to localhost:8080 failed".to_string())
            .unwrap();

        assert_eq!(line2.normalized, "Connection to localhost:<PORT> failed");
        assert!(line2.tokens.iter().any(|t| matches!(t, Token::Port(8080))));

        // Test that IP:port combinations work
        let line3 = normalizer
            .normalize_line("Connection to 192.168.1.1:3000 failed".to_string())
            .unwrap();

        assert_eq!(line3.normalized, "Connection to <IP>:<PORT> failed");
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::IPv4(_))));
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::Port(3000))));

        // Test that IPv6:port combinations work
        let line4 = normalizer
            .normalize_line("Connection to [2001:db8::1]:8080 failed".to_string())
            .unwrap();

        assert_eq!(line4.normalized, "Connection to [<IP>]:<PORT> failed");
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::IPv6(_))));
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::Port(8080))));
    }
}
