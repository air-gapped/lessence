use regex::Regex;
use std::sync::LazyLock;

use super::Token;
use super::{
    duration::DurationDetector, hash::HashDetector, names::NameDetector, network::NetworkDetector,
    path::PathDetector, process::ProcessDetector, timestamp::TimestampDetector, uuid::UuidDetector,
};

// Match quoted strings that contain variable content, including escaped quotes
// This matches strings like "volume-name", "pod-name", and complex strings with \" inside
// Pattern: " followed by any number of (non-quote OR escaped quote), followed by "
static QUOTED_STRING_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:[^"\\]|\\.)*""#).unwrap());

pub struct QuotedStringDetector;

impl QuotedStringDetector {
    /// Detect and replace quoted strings that appear to be variables
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no quoted strings
        if !text.contains('"') {
            return (text.to_string(), Vec::new());
        }
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace all variable quoted strings with placeholder in one pass
        result = QUOTED_STRING_PATTERN
            .replace_all(&result, |caps: &regex::Captures| {
                let quoted_string = caps.get(0).unwrap().as_str();

                // Normalize patterns WITHIN the quoted content before deciding
                let quoted_content = &quoted_string[1..quoted_string.len() - 1]; // Remove quotes
                let mut normalized_content = quoted_content.to_string();

                // Apply EXACT same pattern detection order as main pipeline
                // This ensures consistency and prevents order-dependent bugs

                // 1. TIMESTAMPS (highest priority - most specific format)
                let (new_normalized, _) =
                    TimestampDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 2. PATHS (including full URLs - must run early to preserve URL structure)
                let (new_normalized, _) = PathDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 3. UUIDs (MUST run BEFORE hashes to prevent UUID fragmentation!)
                let (new_normalized, _) = UuidDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 4. NETWORK patterns (IPs, ports, FQDNs)
                let (new_normalized, _) =
                    NetworkDetector::detect_and_replace(&normalized_content, true, true, true);
                normalized_content = new_normalized;

                // 5. HASHES (must run AFTER UUIDs)
                let (new_normalized, _) = HashDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 6. PROCESS IDs
                let (new_normalized, _) = ProcessDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 7. DURATIONS & measurements (including integers)
                let (new_normalized, _) = DurationDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // 8. NAMES (hyphenated component names - generic patterns last)
                let (new_normalized, _) = NameDetector::detect_and_replace(&normalized_content);
                normalized_content = new_normalized;

                // Check for escaped JSON FIRST (highest priority)
                if quoted_content.contains('\\')
                    && (quoted_content.contains(':')
                        || quoted_content.contains('{')
                        || quoted_content.contains('['))
                {
                    // This is escaped JSON or structured data - normalize it
                    tokens.push(Token::QuotedString(quoted_string.to_string()));
                    "<ESCAPED_JSON>".to_string()
                } else if normalized_content != quoted_content {
                    // Normalization changed the content, it contains variable patterns
                    // Store the original quoted string but replace with normalized version
                    tokens.push(Token::QuotedString(quoted_string.to_string()));
                    format!("\"{normalized_content}\"") // Keep it quoted with normalized content
                } else {
                    // No patterns found inside, treat as potential variable name
                    // This covers cases like "volume-name", "pod-uuid" etc.
                    if quoted_string.len() > 25 {
                        // Only very long strings are likely variable names
                        tokens.push(Token::QuotedString(quoted_string.to_string()));
                        "<QUOTED_STRING>".to_string()
                    } else {
                        // Keep shorter quoted strings unchanged (may contain patterns we couldn't detect)
                        quoted_string.to_string()
                    }
                }
            })
            .to_string();

        (result, tokens)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_operation_quoted_strings() {
        let input = r#"operationExecutor.VerifyControllerAttachedVolume started for volume "csi-log" (UniqueName: "kubernetes.io/host-path/01af48d9-3471-4acf-93aa-689c01b31dff-csi-log") pod "csi-rbdplugin-sr56f" (UID: "01af48d9-3471-4acf-93aa-689c01b31dff")"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // "csi-log" (9 chars with quotes) has no detectable patterns and is below 25-char
        // threshold, so it's kept as-is and produces no token. The other 3 quoted strings
        // have internal patterns that get normalized, producing 3 tokens.
        assert_eq!(tokens.len(), 3);

        // Verify normalized output contains expected patterns
        assert!(
            normalized.contains("\"csi-log\""),
            "csi-log should be kept as-is"
        );
        assert!(
            normalized.contains("csi-rbdplugin-<SUFFIX>"),
            "pod name suffix should be normalized"
        );
        assert!(normalized.contains("<UUID>"), "UUID should be normalized");
    }

    #[test]
    fn test_exclude_keywords() {
        let input = r#"status "started" and "finished" operations"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // Should not detect keyword strings
        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input); // Unchanged
    }

    #[test]
    fn test_exclude_short_strings() {
        let input = r#"value "x" and "ab" but "longer-value""#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // "longer-value" (14 chars with quotes) is below the 25-char threshold for
        // unmodified quoted strings, so no tokens are produced
        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input);
    }

    #[test]
    fn test_duration_normalization_in_quotes() {
        let input1 = r#"error "back-off 5m0s restarting failed""#;
        let input2 = r#"error "back-off 10m0s restarting failed""#;

        let (normalized1, tokens1) = QuotedStringDetector::detect_and_replace(input1);
        let (normalized2, tokens2) = QuotedStringDetector::detect_and_replace(input2);

        // Both should normalize to the same pattern since they only differ in duration
        assert_eq!(normalized1, normalized2);
        assert_eq!(
            normalized1,
            r#"error "back-off <DURATION> restarting failed""#
        );

        // Both should detect tokens
        assert_eq!(tokens1.len(), 1);
        assert_eq!(tokens2.len(), 1);
    }

    #[test]
    fn test_multiple_patterns_in_quotes() {
        let test_cases = vec![
            (
                r#"error "connection to 192.168.1.1 failed""#,
                r#"error "connection to <IP> failed""#,
            ),
            (
                r#"error "connection to 10.0.0.1 failed""#,
                r#"error "connection to <IP> failed""#,
            ),
            (
                r#"error "volume abc123def456 not found""#,
                r#"error "volume <HASH> not found""#,
            ),
            (
                r#"error "volume def987fed654321 not found""#,
                r#"error "volume <HASH> not found""#,
            ),
            (
                r#"error "pod 550e8400-e29b-41d4-a716-446655440000 terminated""#,
                r#"error "pod <UUID> terminated""#,
            ),
            (
                r#"error "pod 660f9511-f39c-52e5-b827-557766551111 terminated""#,
                r#"error "pod <UUID> terminated""#,
            ),
            (
                r#"error "process 12345 crashed""#,
                r#"error "process <NUMBER> crashed""#,
            ),
            (
                r#"error "process 67890 crashed""#,
                r#"error "process <NUMBER> crashed""#,
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(
                tokens.len(),
                1,
                "Should detect exactly one quoted string token for: {input}"
            );
        }
    }

    #[test]
    fn test_comprehensive_pattern_grouping() {
        // Test that patterns with different internal variables normalize to the same result
        let inputs = vec![
            r#"error "connection to 192.168.1.1 failed""#,
            r#"error "connection to 10.0.0.1 failed""#,
            r#"error "connection to 172.16.0.1 failed""#,
        ];

        let mut normalized_results = Vec::new();
        for input in &inputs {
            let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);
            normalized_results.push(normalized);
            assert_eq!(tokens.len(), 1);
        }

        // All should normalize to the same pattern
        assert_eq!(normalized_results[0], normalized_results[1]);
        assert_eq!(normalized_results[1], normalized_results[2]);
        assert_eq!(
            normalized_results[0],
            r#"error "connection to <IP> failed""#
        );
    }

    #[test]
    fn test_timestamp_normalization_in_quotes() {
        let test_cases = vec![
            (
                r#"error "backup at 2025-01-20 10:15:30 failed""#,
                r#"error "backup at <TIMESTAMP> failed""#,
            ),
            (
                r#"error "event occurred on 2025-01-20T10:15:30Z""#,
                r#"error "event occurred on <TIMESTAMP>""#,
            ),
            (
                r#"error "log from Jan 20 10:15:30""#,
                r#"error "log from <TIMESTAMP>""#,
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(tokens.len(), 1);
        }
    }

    #[test]
    fn test_path_normalization_in_quotes() {
        let test_cases = vec![
            (
                r#"error "file /var/log/app.log missing""#,
                r#"error "file <PATH> missing""#,
            ),
            (
                r#"error "cannot read /etc/config/settings.yaml""#,
                r#"error "cannot read <PATH>""#,
            ),
            (
                r#"error "http://192.168.1.1:8080/api/v1 unreachable""#,
                r#"error "<PATH> unreachable""#,
            ),
            // Windows paths with backslashes trigger the escaped JSON detection
            // (content has both '\' and ':' which matches the escaped JSON heuristic)
            (
                r#"error "path C:\Windows\System32\config invalid""#,
                r"error <ESCAPED_JSON>",
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(tokens.len(), 1);
        }
    }

    // ---- Mutant-killing: boundary conditions on quote detection ----

    #[test]
    fn quoted_string_escaped_json_bracket_only() {
        // Kills mutant: `|| with &&` on line 78 (contains('['))
        // Input has backslash + bracket but NOT colon and NOT brace
        let input = r#"data "value\[index\]more" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+bracket should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_colon_only() {
        // Input has backslash + colon but NOT brace and NOT bracket
        let input = r#"data "key\:value\:end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+colon should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_brace_only() {
        // Input has backslash + brace but NOT colon and NOT bracket
        let input = r#"data "obj\{inner\}end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+brace should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_long_unmodified_threshold() {
        // Kills mutant: `> 25` → `>= 25` (line ~91)
        // The threshold applies when no normalization patterns match inside the quoted content.
        // Use content that no detector will normalize (no IPs, timestamps, UUIDs, names, etc.)
        // A simple repeated word with spaces — normalizers won't touch it.
        // Content must be plain text that doesn't trigger ANY detector.

        // We need quoted_string.len() == 25
        // quoted_string includes the quotes: "..." = content_len + 2
        // For len == 25, content_len = 23
        // For len == 26, content_len = 24
        // Use spaces and lowercase words to avoid pattern detection
        let content_23 = "it is a very simple tex"; // 23 chars
        assert_eq!(content_23.len(), 23);
        let input_25 = format!(r#"x "{content_23}""#);
        let (result25, tokens25) = QuotedStringDetector::detect_and_replace(&input_25);
        assert_eq!(tokens25.len(), 0, "25-char quoted string should NOT produce token: {result25}");
        assert_eq!(result25, input_25);

        // 24 chars content + 2 quotes = 26 total → > 25 → replaced
        let content_24 = "it is a very simple text";
        assert_eq!(content_24.len(), 24);
        let input_26 = format!(r#"x "{content_24}""#);
        let (result26, tokens26) = QuotedStringDetector::detect_and_replace(&input_26);
        assert_eq!(tokens26.len(), 1, "26-char quoted string should produce token: {result26}");
        assert!(result26.contains("<QUOTED_STRING>"), "should be replaced: {result26}");
    }

    #[test]
    fn test_order_critical_patterns() {
        // Test UUID detection happens before hash detection
        let uuid_input = r#"error "pod 550e8400-e29b-41d4-a716-446655440000 terminated""#;
        let (uuid_result, _) = QuotedStringDetector::detect_and_replace(uuid_input);
        assert_eq!(uuid_result, r#"error "pod <UUID> terminated""#);
        assert!(
            !uuid_result.contains("<HASH>"),
            "UUID should not be fragmented into hashes"
        );

        // Test URL paths are preserved (path detection before network)
        let url_input = r#"error "endpoint http://192.168.1.1:8080/api/v1/users down""#;
        let (url_result, _) = QuotedStringDetector::detect_and_replace(url_input);
        assert_eq!(url_result, r#"error "endpoint <PATH> down""#);
        assert!(
            !url_result.contains("<IP>"),
            "URL should be preserved as complete path"
        );

        // Test complex pattern with multiple types
        let complex_input = r#"error "backup of /data/db at 2025-01-20 10:15:30 for pod 550e8400-e29b-41d4-a716-446655440000 failed""#;
        let (complex_result, _) = QuotedStringDetector::detect_and_replace(complex_input);
        assert_eq!(
            complex_result,
            r#"error "backup of <PATH> at <TIMESTAMP> for pod <UUID> failed""#
        );
    }
}
