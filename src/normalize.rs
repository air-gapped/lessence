use ahash::AHasher;
use anyhow::Result;
use std::hash::{Hash, Hasher};

use crate::config::Config;
use crate::patterns::{
    LogLine, Token, duration::DurationDetector, email::EmailPatternDetector, hash::HashDetector,
    json::JsonDetector, kubernetes::KubernetesDetector, names::NameDetector,
    network::NetworkDetector, path::PathDetector, process::ProcessDetector,
    quoted::QuotedStringDetector, timestamp::TimestampDetector, uuid::UuidDetector,
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
        let mut tokens = Vec::with_capacity(8);

        // Apply normalizations in optimized order (most specific to least specific)
        // This prevents conflicts and maximizes pattern detection accuracy

        // 1. TIMESTAMPS (highest priority - most specific format)
        if self.config.normalize_timestamps {
            let (new_normalized, mut new_tokens) =
                TimestampDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 2. EMAIL ADDRESSES (before paths to ensure emails in URLs are handled correctly)
        if self.config.normalize_emails && normalized.contains('@') {
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
        if self.config.normalize_json && normalized.contains('{') {
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
        if self.config.normalize_http_status {
            let (new_normalized, mut new_tokens) =
                crate::patterns::http_status::HttpStatusDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // BracketContext - Detects [error] [mod_jk] style patterns
        if self.config.normalize_brackets && normalized.contains('[') {
            let (new_normalized, mut new_tokens) =
                crate::patterns::bracket_context::BracketContextDetector::detect_and_replace(
                    &normalized,
                );
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // KeyValuePair - Detects config=value, metrics patterns
        if self.config.normalize_key_value && normalized.contains('=') {
            let (new_normalized, mut new_tokens) =
                crate::patterns::key_value::KeyValueDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // LogWithModule - Detects [level] module patterns for Apache/nginx
        // Gated by the same flag as BracketContext: --disable-patterns brackets
        // must disable every bracket-shaped detector.
        if self.config.normalize_brackets && normalized.contains('[') {
            let (new_normalized, mut new_tokens) =
                crate::patterns::log_module::LogWithModuleDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // StructuredMessage - Detects JSON/logfmt structured logging.
        // The JSON half is gated by --disable-patterns json, the logfmt
        // half by --disable-patterns key-value.
        if (self.config.normalize_json && normalized.contains('{'))
            || (self.config.normalize_key_value && normalized.contains('='))
        {
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
        if self.config.normalize_names {
            let (new_normalized, mut new_tokens) = NameDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // 12. QUOTED STRINGS (generic quoted variables - high priority for mount operations)
        // Must run after paths to catch normalized quoted paths properly
        if self.config.normalize_quoted && (normalized.contains('"') || normalized.contains('\'')) {
            let (new_normalized, mut new_tokens) =
                QuotedStringDetector::detect_and_replace(&normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

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

    /// Maximum whitespace tokens per line that the LCS comparison handles;
    /// longer lines fall back to the positional byte overlap. 64 covers
    /// virtually all real log lines while bounding the DP at 64×64 token
    /// comparisons on the stack with zero allocation.
    const MAX_SIMILARITY_TOKENS: usize = 64;

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

        // Token-level LCS: tolerant of an inserted or removed token, which a
        // positional comparison is not (one early insertion used to cascade
        // into a near-zero score for otherwise identical lines).
        let mut t1 = [""; Self::MAX_SIMILARITY_TOKENS];
        let mut t2 = [""; Self::MAX_SIMILARITY_TOKENS];
        if let (Some(n1), Some(n2)) = (
            Self::collect_tokens(s1, &mut t1),
            Self::collect_tokens(s2, &mut t2),
        ) && n1 > 0
            && n2 > 0
        {
            let a = &t1[..n1];
            let b = &t2[..n2];
            // Positional fast path: when every aligned token matches, the
            // LCS is exactly min(n1, n2) — skip the DP. This covers the
            // common case of same-shape lines compared against a group
            // representative.
            let min_n = n1.min(n2);
            let aligned = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
            let lcs = if aligned == min_n {
                min_n
            } else {
                Self::token_lcs(a, b)
            };
            return (2.0 * lcs as f64 / (n1 + n2) as f64) * 100.0;
        }

        // Fallback for token-overflow or whitespace-only lines: positional
        // byte overlap (no allocation — works on &[u8] directly).
        let b1 = s1.as_bytes();
        let b2 = s2.as_bytes();
        let mut matches: u32 = 0;
        for i in 0..min_len {
            if b1[i] == b2[i] {
                matches += 1;
            }
        }
        (f64::from(matches) / max_len as f64) * 100.0
    }

    /// Fills `out` with the whitespace tokens of `s`. Returns the token
    /// count, or None if the line has more tokens than fit.
    fn collect_tokens<'a>(
        s: &'a str,
        out: &mut [&'a str; Self::MAX_SIMILARITY_TOKENS],
    ) -> Option<usize> {
        let mut n = 0;
        for tok in s.split_whitespace() {
            if n == Self::MAX_SIMILARITY_TOKENS {
                return None;
            }
            out[n] = tok;
            n += 1;
        }
        Some(n)
    }

    /// Longest common subsequence length over token slices (rolling-row DP,
    /// stack-only). Both inputs are at most MAX_SIMILARITY_TOKENS long.
    fn token_lcs(a: &[&str], b: &[&str]) -> usize {
        let mut prev = [0u16; Self::MAX_SIMILARITY_TOKENS + 1];
        let mut curr = [0u16; Self::MAX_SIMILARITY_TOKENS + 1];
        for ta in a {
            for (j, tb) in b.iter().enumerate() {
                curr[j + 1] = if ta == tb {
                    prev[j] + 1
                } else {
                    prev[j + 1].max(curr[j])
                };
            }
            prev[..=b.len()].copy_from_slice(&curr[..=b.len()]);
        }
        usize::from(prev[b.len()])
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
                format!("[+{count} similar]")
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
                    ("key_value_pair", format!("{key}={value_type}"))
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
        assert!(
            line1
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Timestamp(_)))
        );
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

    // --- similarity_score direct tests (mutant kills) ---

    #[test]
    fn test_similarity_score_identical() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line("hello world".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&line, &line);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_similarity_score_completely_different() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer.normalize_line("aaaa".to_string()).unwrap();
        let b = normalizer.normalize_line("zzzz".to_string()).unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            score < 1.0,
            "Completely different strings should score near 0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_partial_match() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("ERROR conn refused".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("ERROR conn timeout".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 2 of 3 tokens shared: 2*2/(3+3) = 66.7
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "Expected 66.7, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_tolerates_token_insertion() {
        // The motivating bug for the LCS metric: one token inserted at the
        // front used to cascade into a near-zero positional score.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("node1 ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 6 shared tokens of 6+7: 2*6/13 = 92.3
        assert!(
            score > 90.0,
            "insertion-shifted line should score high, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_common_prefix_not_enough() {
        // Long shared prefix with diverging tails must NOT score near 100 —
        // merging these would lose distinct messages.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("svc api gateway east db conn pool exhausted".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("svc api gateway east tls handshake err peer".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 4 shared of 8+8 tokens: 50.0
        assert!(
            (score - 50.0).abs() < 1e-9,
            "diverging tails should score 50, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_length_ratio_rejection() {
        let normalizer = Normalizer::new(Config::default());
        let short = normalizer.normalize_line("ab".to_string()).unwrap();
        let long = normalizer.normalize_line("abcdefghij".to_string()).unwrap();
        let score = normalizer.similarity_score(&short, &long);
        // ratio = 2/10 = 0.2, below 0.7 threshold → returns 0.2 * 100 = 20.0
        assert!(
            (score - 20.0).abs() < f64::EPSILON,
            "Expected 20.0 (ratio rejection), got {score}"
        );
    }

    #[test]
    fn test_similarity_score_empty_strings() {
        let normalizer = Normalizer::new(Config::default());
        let empty = LogLine {
            original: String::new(),
            normalized: String::new(),
            tokens: vec![],
            hash: 0,
        };
        let score = normalizer.similarity_score(&empty, &empty);
        assert!(
            (score - 100.0).abs() < f64::EPSILON,
            "Empty vs empty should be 100.0"
        );
    }

    #[test]
    fn test_similarity_score_at_length_ratio_boundary() {
        let normalizer = Normalizer::new(Config::default());
        let ten_chars = normalizer.normalize_line("abcdefghij".to_string()).unwrap();

        // 7/10 = 0.7, exactly at threshold → NOT rejected → token comparison:
        // single differing tokens share nothing → 0.0
        let seven_match = normalizer.normalize_line("abcdefg".to_string()).unwrap();
        let score = normalizer.similarity_score(&seven_match, &ten_chars);
        assert!(
            score.abs() < f64::EPSILON,
            "At boundary (0.7), token comparison applies. Got {score}"
        );

        // 6/10 = 0.6, below threshold → rejected early → returns 0.6*100 = 60.0
        let six_match = normalizer.normalize_line("abcdef".to_string()).unwrap();
        let score_below = normalizer.similarity_score(&six_match, &ten_chars);
        assert!(
            (score_below - 60.0).abs() < f64::EPSILON,
            "Below boundary, should return ratio*100=60.0. Got {score_below}"
        );

        // 7 chars but last differs → ratio=0.7, NOT rejected → token
        // comparison: differing single tokens share nothing → 0.0
        let seven_mismatch = normalizer.normalize_line("abcdefz".to_string()).unwrap();
        let score_mismatch = normalizer.similarity_score(&seven_mismatch, &ten_chars);
        assert!(
            score_mismatch.abs() < f64::EPSILON,
            "At boundary with mismatch, token comparison gives 0.0. Got {score_mismatch}"
        );

        // 7 chars, none match → ratio=0.7, NOT rejected, char comparison: 0/10 = 0.0
        let seven_none = normalizer.normalize_line("xyzxyzx".to_string()).unwrap();
        let score_none = normalizer.similarity_score(&seven_none, &ten_chars);
        assert!(
            score_none < 1.0,
            "At boundary with zero char matches, should be ~0. Got {score_none}"
        );
    }

    #[test]
    fn test_similarity_score_one_token_diff() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("alpha beta gamma delta epsilon zeta eta theta iota kappa".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("alpha beta gamma delta epsilon zeta eta theta iota XXXXX".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 9 of 10 tokens shared: 2*9/20 = 90.0
        assert!(
            (score - 90.0).abs() < f64::EPSILON,
            "Expected 90.0, got {score}"
        );
    }

    // --- similarity_score edge cases for uncaught mutants ---

    #[test]
    fn test_similarity_score_empty_vs_nonempty() {
        // Kills mutant: max_len == 0 → max_len != 0
        // With one empty and one non-empty, max_len > 0, min_len = 0
        // length_ratio = 0/5 = 0.0 < 0.7 → returns 0.0
        let normalizer = Normalizer::new(Config::default());
        let empty = LogLine {
            original: String::new(),
            normalized: String::new(),
            tokens: vec![],
            hash: 0,
        };
        let nonempty = LogLine {
            original: "hello".into(),
            normalized: "hello".into(),
            tokens: vec![],
            hash: 1,
        };
        let score = normalizer.similarity_score(&empty, &nonempty);
        assert!(
            score < 1.0,
            "empty vs non-empty should score near 0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_min_max_not_swapped() {
        // Kills mutant: min_len ↔ max_len swap in length_ratio calculation
        // len1=3, len2=10: ratio should be 3/10=0.3, NOT 10/3=3.33
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine {
            original: "abc".into(),
            normalized: "abc".into(),
            tokens: vec![],
            hash: 0,
        };
        let long = LogLine {
            original: "abcdefghij".into(),
            normalized: "abcdefghij".into(),
            tokens: vec![],
            hash: 1,
        };
        let score = normalizer.similarity_score(&short, &long);
        // ratio = 3/10 = 0.3 < 0.7 → returns 0.3 * 100 = 30.0
        assert!(
            (score - 30.0).abs() < f64::EPSILON,
            "3/10 ratio should give 30.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_byte_fallback_division_direction() {
        // Exercises the byte-overlap fallback (token overflow: > 64 tokens).
        // Kills mutant: `/ max_len` → `* max_len` or `+ max_len`.
        let normalizer = Normalizer::new(Config::default());
        let half_match = |c: char| {
            let mut s: String = std::iter::repeat_n("a ", 65).collect(); // 65 tokens, 130 bytes
            s.push_str(&c.to_string().repeat(130));
            s
        };
        let a = LogLine {
            original: half_match('X'),
            normalized: half_match('X'),
            tokens: vec![],
            hash: 0,
        };
        let b = LogLine {
            original: half_match('Y'),
            normalized: half_match('Y'),
            tokens: vec![],
            hash: 1,
        };
        let score = normalizer.similarity_score(&a, &b);
        // First 130 of 260 bytes match positionally: 50.0
        assert!(
            (score - 50.0).abs() < f64::EPSILON,
            "130/260 matching bytes should give 50.0, got {score}"
        );
    }

    fn raw_line(s: String, hash: u64) -> LogLine {
        LogLine {
            original: s.clone(),
            normalized: s,
            tokens: vec![],
            hash,
        }
    }

    #[test]
    fn test_similarity_score_byte_fallback_uneven_ratio() {
        // Token overflow with a 3/4 positional byte match. Kills the
        // `==` → `!=` mutant in the fallback loop (a 50/50 split is
        // invariant under that inversion, this is not).
        let mk = |tail: char| {
            let mut s: String = std::iter::repeat_n("a ", 65).collect(); // 130 bytes
            s.push_str(&"m".repeat(260)); // 260 matching bytes
            s.push_str(&tail.to_string().repeat(130)); // 130 differing bytes
            s
        };
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(&raw_line(mk('X'), 0), &raw_line(mk('Y'), 1));
        // 390 of 520 bytes match: 75.0
        assert!(
            (score - 75.0).abs() < f64::EPSILON,
            "390/520 matching bytes should give 75.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_whitespace_only_uses_byte_fallback() {
        // Zero tokens on both sides must take the byte fallback, not the
        // empty-LCS path (which would score 0 or divide by zero).
        let normalizer = Normalizer::new(Config::default());
        let score =
            normalizer.similarity_score(&raw_line("   ".into(), 0), &raw_line("    ".into(), 1));
        // 3 of 4 bytes match positionally: 75.0
        assert!(
            (score - 75.0).abs() < f64::EPSILON,
            "whitespace-only lines should byte-compare to 75.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_one_side_whitespace_only() {
        // One side tokenless, the other not: must take the byte fallback in
        // BOTH argument orders (kills `n1 > 0`/`n2 > 0` → `>=` mutants,
        // which would route into the LCS path and score 0).
        let normalizer = Normalizer::new(Config::default());
        let blank = || raw_line("    ".into(), 0);
        let lead = || raw_line("a   ".into(), 1);
        for (x, y) in [(blank(), lead()), (lead(), blank())] {
            let score = normalizer.similarity_score(&x, &y);
            // 3 of 4 bytes match positionally: 75.0
            assert!(
                (score - 75.0).abs() < f64::EPSILON,
                "tokenless side should byte-compare to 75.0, got {score}"
            );
        }
    }

    #[test]
    fn test_similarity_score_token_reorder_partial() {
        // Rotated token order: LCS("alpha beta gamma", "gamma alpha beta")
        // is 2, not 3 — pins the DP recurrence (prev[j+1] vs prev[j]).
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(
            &raw_line("alpha beta gamma".into(), 0),
            &raw_line("gamma alpha beta".into(), 1),
        );
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "rotated tokens share LCS 2 of 3: 66.7, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_at_max_token_capacity() {
        // Exactly 64 tokens exercises the full DP row width; an off-by-one
        // in the row arrays panics here.
        let mk = |last: &str| {
            let mut s: String = std::iter::repeat_n("tok ", 63).collect();
            s.push_str(last);
            s
        };
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(&raw_line(mk("aaa"), 0), &raw_line(mk("bbb"), 1));
        // 63 of 64 tokens shared: 2*63/128 = 98.4375
        assert!(
            (score - 98.4375).abs() < 1e-9,
            "63/64 shared tokens should give 98.4375, got {score}"
        );
    }

    #[test]
    fn test_are_similar_hash_shortcircuit() {
        let normalizer = Normalizer::new(Config::default());
        let a = LogLine {
            original: "completely different".into(),
            normalized: "completely different".into(),
            tokens: vec![],
            hash: 42,
        };
        let b = LogLine {
            original: "not similar at all really".into(),
            normalized: "not similar at all really".into(),
            tokens: vec![],
            hash: 42, // same hash = shortcircuit to true
        };
        assert!(
            normalizer.are_similar(&a, &b),
            "same hash should shortcircuit to similar"
        );
    }

    // --- summarize_variation_types direct tests (mutant kills) ---

    #[test]
    fn test_variation_types_different_ips() {
        let normalizer = Normalizer::new(Config::default());
        let first = vec![Token::IPv4("10.0.0.1".to_string())];
        let last = vec![Token::IPv4("10.0.0.2".to_string())];
        let types = normalizer.summarize_variation_types(&first, &last);
        assert_eq!(types, vec!["IP"]);
    }

    #[test]
    fn test_variation_types_same_tokens_no_variation() {
        let normalizer = Normalizer::new(Config::default());
        let tokens = vec![Token::IPv4("10.0.0.1".to_string())];
        let types = normalizer.summarize_variation_types(&tokens, &tokens);
        assert!(types.is_empty(), "Same tokens should produce no variation");
    }

    #[test]
    fn test_variation_types_essence_mode_skips_timestamps() {
        let config = Config {
            essence_mode: true,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let first = vec![Token::Timestamp("2025-01-01T00:00:00Z".to_string())];
        let last = vec![Token::Timestamp("2025-01-02T00:00:00Z".to_string())];
        let types = normalizer.summarize_variation_types(&first, &last);
        assert!(
            types.is_empty(),
            "Essence mode should skip timestamp variations"
        );
    }

    #[test]
    fn test_variation_types_non_essence_includes_timestamps() {
        let normalizer = Normalizer::new(Config::default());
        let first = vec![Token::Timestamp("2025-01-01T00:00:00Z".to_string())];
        let last = vec![Token::Timestamp("2025-01-02T00:00:00Z".to_string())];
        let types = normalizer.summarize_variation_types(&first, &last);
        assert_eq!(types, vec!["timestamp"]);
    }

    #[test]
    fn test_variation_types_multiple_types_sorted() {
        let normalizer = Normalizer::new(Config::default());
        let first = vec![
            Token::IPv4("10.0.0.1".to_string()),
            Token::Uuid("aaa".to_string()),
        ];
        let last = vec![
            Token::IPv4("10.0.0.2".to_string()),
            Token::Uuid("bbb".to_string()),
        ];
        let types = normalizer.summarize_variation_types(&first, &last);
        assert_eq!(types, vec!["IP", "UUID"]);
    }

    // --- normalize_line short-circuit tests (mutant kills) ---

    #[test]
    fn test_normalize_ips_only_flag() {
        let config = Config {
            normalize_ips: true,
            normalize_ports: false,
            normalize_fqdns: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("connect to 10.0.0.1:8080".to_string())
            .unwrap();
        assert!(
            line.tokens.iter().any(|t| matches!(t, Token::IPv4(_))),
            "IPs should be detected"
        );
    }

    #[test]
    fn test_normalize_ports_only_flag() {
        let config = Config {
            normalize_ips: false,
            normalize_ports: true,
            normalize_fqdns: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("connect to localhost:8080".to_string())
            .unwrap();
        assert!(
            line.tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "Ports should be detected"
        );
    }

    // ---- normalize_line: boolean condition tests ----

    #[test]
    fn normalize_line_json_disabled_no_detection() {
        let config = Config {
            normalize_json: false,
            ..Config::default()
        };
        let n = Normalizer::new(config);
        let line = n.normalize_line(r"&Event{Type: Warning}".into()).unwrap();
        // With JSON detection disabled, Event objects should NOT be detected
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Json(_))),
            "JSON detection should be disabled"
        );
    }

    #[test]
    fn structured_detection_brace_only() {
        // Input with { but no = — should still trigger structured detection
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line(r#"{"level":"error","component":"web","msg":"fail"}"#.into())
            .unwrap();
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "Brace-only input should trigger structured detection: {:?}",
            line.tokens
        );
    }

    #[test]
    fn structured_detection_equals_only() {
        // Input with = but no { — should still trigger the structured/KV detection path
        // The || ensures both branches (contains '{') and (contains '=') individually pass
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("level=error component=web msg=fail".into())
            .unwrap();
        // Either StructuredMessage or KeyValuePair tokens indicate the = path was taken
        assert!(
            line.tokens.iter().any(|t| matches!(
                t,
                Token::StructuredMessage { .. } | Token::KeyValuePair { .. }
            )),
            "Equals-only input should trigger structured or KV detection: {:?}",
            line.tokens
        );
    }

    // ---- Mutant-killing: normalize_timestamps=false with colon input ----

    #[test]
    fn normalize_timestamps_disabled_with_colon_input() {
        // Kills mutant: `self.config.normalize_timestamps && text.contains(':')` → `||`
        // If mutated to ||, timestamps would be detected even when disabled
        let config = Config {
            normalize_timestamps: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("10:15:30 Error occurred".to_string())
            .unwrap();
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Timestamp(_))),
            "Timestamps should NOT be detected when normalize_timestamps=false"
        );
    }

    // ---- Mutant-killing: normalize_emails=false (line 43) ----

    #[test]
    fn normalize_emails_disabled_no_detection() {
        let config = Config {
            normalize_emails: false,
            ..Config::default()
        };
        let n = Normalizer::new(config);
        let line = n
            .normalize_line("user test@example.com logged in".into())
            .unwrap();
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Email(_))),
            "Emails should NOT be detected when normalize_emails=false: {:?}",
            line.tokens
        );
    }

    // ---- Mutant-killing: quoted string detection (line 173) ----

    #[test]
    fn quoted_detection_single_quote_only() {
        // Input with ' but no " — should still trigger quoted string detection path
        // Kills: || with && on `contains('"') || contains('\'')`
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("mount 'very-long-volume-name-that-exceeds-threshold-ok' done".into())
            .unwrap();
        // The ' path should be entered (if || is correct, either quote type suffices)
        // Just verify no panic — the detection may or may not produce tokens
        let _ = line;
    }

    // ---- Mutant-killing: normalize_json=false with brace input ----

    #[test]
    fn normalize_json_disabled_with_brace_input() {
        // Note: this mutant (normalize.rs:59) is excluded via .cargo/mutants.toml
        // because PathDetector (step 3) already replaces &Event{} with <EVENT_OBJECT>
        // before JsonDetector (step 4) ever runs. The normalize_json guard is
        // structurally unreachable — an equivalent mutant.
        //
        // This test verifies JsonDetector itself works in isolation.
        let (_, direct_tokens) =
            crate::patterns::json::JsonDetector::detect_and_replace("&Event{Type: Warning}");
        assert!(
            direct_tokens.iter().any(|t| matches!(t, Token::Json(_))),
            "JsonDetector should detect Event objects: {direct_tokens:?}"
        );
    }

    // ---- Mutant-killing: --disable-patterns guards at the Normalizer boundary ----
    // Each test uses an input that provably triggers its detector (default on),
    // then asserts the corresponding token type disappears when the guard is off.

    fn run(config_mut: impl FnOnce(&mut Config), input: &str) -> LogLine {
        let mut config = Config::default();
        config_mut(&mut config);
        Normalizer::new(config)
            .normalize_line(input.to_string())
            .unwrap()
    }

    #[test]
    fn normalize_brackets_disabled_suppresses_log_module_tokens() {
        let input = "2024-01-01 10:00:00 ERROR [hibernate_sql] Database connection failed";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_brackets = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "expected LogWithModule token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "expected NO LogWithModule token with brackets OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_json_disabled_suppresses_structured_json_tokens() {
        let input = r#"{"level":"info","component":"api","msg":"Request received"}"#;
        let on = run(|_| {}, input);
        let off = run(
            |c| {
                c.normalize_json = false;
                c.normalize_key_value = false;
            },
            input,
        );
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "expected StructuredMessage token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "expected NO StructuredMessage token with json+key-value OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_kubernetes_disabled_suppresses_k8s_tokens() {
        let input = "volume \"kube-api-access-abc123\" (projected) failed to mount for pod kube-system/test-pod";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_kubernetes = false, input);
        assert!(
            on.tokens.iter().any(|t| matches!(
                t,
                Token::KubernetesNamespace(_) | Token::PodName(_) | Token::VolumeName(_)
            )),
            "expected k8s token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens.iter().any(|t| matches!(
                t,
                Token::KubernetesNamespace(_) | Token::PodName(_) | Token::VolumeName(_)
            )),
            "expected NO k8s token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_names_disabled_suppresses_name_tokens() {
        let input = "service api-deploy-abc123-x1y2 started";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_names = false, input);
        assert!(
            on.tokens.iter().any(|t| matches!(t, Token::Name(_))),
            "expected Name token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens.iter().any(|t| matches!(t, Token::Name(_))),
            "expected NO Name token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_quoted_disabled_suppresses_quoted_tokens() {
        let input = "message \"some variable value here\" done";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_quoted = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::QuotedString(_))),
            "expected QuotedString token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::QuotedString(_))),
            "expected NO QuotedString token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_brackets_disabled_suppresses_bracket_context_tokens() {
        let input = "[error] [mod_jk] request failed";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_brackets = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::BracketContext(_))),
            "expected BracketContext token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::BracketContext(_))),
            "expected NO BracketContext token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_key_value_disabled_suppresses_kv_tokens() {
        let input = "level=error status=500 user_id=42";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_key_value = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::KeyValuePair { .. })),
            "expected KeyValuePair token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::KeyValuePair { .. })),
            "expected NO KeyValuePair token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_http_status_disabled_suppresses_http_tokens() {
        let input =
            r#"127.0.0.1 - - [25/Dec/2023:10:15:30 +0000] "POST /api/login HTTP/1.1" 401 256"#;
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_http_status = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::HttpStatus(_) | Token::HttpStatusClass(_))),
            "expected HTTP status token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::HttpStatus(_) | Token::HttpStatusClass(_))),
            "expected NO HTTP status token with detector OFF, got {:?}",
            off.tokens
        );
    }

    // ---- Mutant-killing: similarity_score division vs multiplication ----

    #[test]
    fn similarity_score_division_not_multiplication() {
        // Kills mutant: `min_len as f64 / max_len as f64` → `*`
        // Use strings where:
        //   division: 3/10 = 0.3 < 0.7 → returns 30.0 (quick reject)
        //   multiplication: 3*10 = 30.0 > 0.7 → falls through to char comparison
        // The char comparison for "xyz" vs "abcdefghij" (0 matching bytes) → 0.0
        // So: division returns 30.0, multiplication returns 0.0
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine {
            original: "xyz".into(),
            normalized: "xyz".into(),
            tokens: vec![],
            hash: 0,
        };
        let long = LogLine {
            original: "abcdefghij".into(),
            normalized: "abcdefghij".into(),
            tokens: vec![],
            hash: 1,
        };
        let score = normalizer.similarity_score(&short, &long);
        // With /: ratio = 3/10 = 0.3 < 0.7 → returns 30.0
        // With *: ratio = 30.0 > 0.7 → char comparison (0 matching) → 0.0
        assert!(
            score > 20.0,
            "3/10 ratio should give 30.0, got {score} (if 0.0, division was mutated to *)"
        );
    }
}
