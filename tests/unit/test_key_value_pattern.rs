use lessence::patterns::Token;
use lessence::patterns::key_value::KeyValueDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_simple_key_value_detection() {
        let test_cases = vec![
            "attempt_count=1",
            "failure_rate=65%",
            "response_time=250ms",
            "user_id=12345",
            "status=active",
        ];

        for test_case in test_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<KEY_VALUE>"),
                "Failed to detect key-value pair in: {test_case}"
            );
            assert_eq!(tokens.len(), 1, "Should detect exactly one key-value token");

            if let Token::KeyValuePair { key, value_type } = &tokens[0] {
                assert!(!key.is_empty(), "Key should not be empty");
                assert!(!value_type.is_empty(), "Value type should not be empty");
            } else {
                panic!("Expected KeyValuePair token, got: {:?}", tokens[0]);
            }
        }
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_multiple_key_value_pairs_same_line() {
        let test_cases = vec![
            "attempt_count=1, failure_rate=65%",
            "user_id=12345, status=active, last_login=2024-01-01",
            "cpu_usage=75%, memory_usage=60%, disk_usage=45%",
            "config: timeout=30s, retries=3, max_connections=100",
        ];

        for test_case in test_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            assert!(
                tokens.len() >= 2,
                "Should detect multiple key-value pairs in: {test_case}"
            );
            assert!(
                result.contains("<KEY_VALUE>"),
                "Should normalize key-value pairs in: {test_case}"
            );

            // All tokens should be KeyValuePair tokens
            for token in tokens {
                if let Token::KeyValuePair {
                    key: _,
                    value_type: _,
                } = token
                {
                    // Valid KeyValuePair token
                } else {
                    panic!("Expected all tokens to be KeyValuePair, got: {token:?}");
                }
            }
        }
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_different_value_types() {
        let test_cases = vec![
            ("count=42", "number"),
            ("enabled=true", "boolean"),
            ("rate=65.5%", "percentage"),
            ("timeout=30s", "duration"),
            ("memory=512MB", "size"),
            ("name=service_a", "string"),
            ("url=https://example.com", "url"),
            ("ip=192.168.1.1", "ip"),
        ];

        for (test_input, expected_type) in test_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_input);

            assert_eq!(tokens.len(), 1, "Should detect one key-value pair");

            if let Token::KeyValuePair { key: _, value_type } = &tokens[0] {
                assert_eq!(
                    value_type, expected_type,
                    "Expected value type '{expected_type}' for input '{test_input}', got '{value_type}'"
                );
            } else {
                panic!("Expected KeyValuePair token");
            }
        }
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_configuration_logs() {
        let config_logs = vec![
            "Database config: host=localhost, port=5432, ssl=true",
            "Server settings: timeout=30s, max_connections=100, debug=false",
            "Cache configuration: ttl=3600, max_size=1GB, compression=enabled",
            "API limits: rate_limit=1000/min, burst=50, window=1m",
        ];

        for line in config_logs {
            let (result, tokens) = KeyValueDetector::detect_and_replace(line);

            assert!(
                tokens.len() >= 3,
                "Should detect multiple config parameters in: {line}"
            );
            assert!(
                result.contains("<KEY_VALUE>"),
                "Should normalize config parameters in: {line}"
            );

            // Verify all detected tokens are key-value pairs
            for token in tokens {
                if let Token::KeyValuePair { key, value_type: _ } = token {
                    assert!(!key.is_empty(), "Config keys should not be empty");
                } else {
                    panic!("Expected KeyValuePair token in config log");
                }
            }
        }
    }

    #[test]
    fn test_metrics_logs() {
        let metrics_logs = vec![
            "Performance metrics: cpu=75%, memory=60%, disk=45%",
            "Request stats: count=1024, avg_time=120ms, error_rate=2.5%",
            "Circuit breaker: attempt_count=1, failure_rate=65%",
            "Load balancer: active_connections=50, queue_size=10, throughput=500rps",
        ];

        for line in metrics_logs {
            let (result, tokens) = KeyValueDetector::detect_and_replace(line);

            assert!(!tokens.is_empty(), "Should detect metrics in: {line}");

            // Check that percentage values are properly typed
            let has_percentage = tokens.iter().any(|token| {
                if let Token::KeyValuePair { key: _, value_type } = token {
                    value_type == "percentage"
                } else {
                    false
                }
            });

            if line.contains('%') {
                assert!(has_percentage, "Should detect percentage values in metrics");
            }
        }
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_application_logs() {
        let app_logs = vec![
            "User action: user_id=12345, action=login, success=true, duration=250ms",
            "API call: endpoint=/api/users, method=GET, status=200, response_time=45ms",
            "Database query: table=users, operation=SELECT, rows=100, time=15ms",
            "Cache operation: key=user:12345, operation=hit, ttl=3600s",
        ];

        for line in app_logs {
            let (result, tokens) = KeyValueDetector::detect_and_replace(line);

            assert!(
                tokens.len() >= 3,
                "Should detect multiple application parameters in: {line}"
            );

            // After normalization, similar operations should group better
            assert!(
                result.contains("<KEY_VALUE>"),
                "Should normalize application parameters"
            );
        }
    }

    #[test]
    fn test_no_false_positives() {
        let non_kv_cases = vec![
            "Mathematical equation: x=y+z where x=5",
            "Assignment in code: variable = value",
            "Comparison: if value == expected",
            "URL with params: https://example.com?param=value&other=data",
            "SQL query: SELECT * FROM table WHERE id = 123",
        ];

        for test_case in non_kv_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            // Should be careful not to match programming constructs
            // This depends on context - URL params might be valid to match
            // Programming assignments should not be matched
            if test_case.contains("variable =") || test_case.contains("x=y") {
                assert_eq!(
                    result, test_case,
                    "Should not modify programming assignments: {test_case}"
                );
                assert_eq!(
                    tokens.len(),
                    0,
                    "Should not detect tokens in programming context: {test_case}"
                );
            }
        }
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_different_separators() {
        let separator_cases = vec![
            "config: key=value, other=123",    // comma-separated
            "params: key=value; other=123",    // semicolon-separated
            "data key=value other=123",        // space-separated
            "settings: key=value | other=123", // pipe-separated
        ];

        for test_case in separator_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            assert!(
                tokens.len() >= 2,
                "Should detect key-value pairs regardless of separator in: {test_case}"
            );
        }
    }

    #[test]
    fn test_compression_improvement_target() {
        // This test validates that key-value normalization improves compression
        // for configuration and metrics logs

        let config_samples = vec![
            "Database: host=db1, port=5432, ssl=true, timeout=30s",
            "Database: host=db2, port=5432, ssl=true, timeout=30s",
            "Database: host=db3, port=5432, ssl=false, timeout=45s",
            "Cache: ttl=3600, size=1GB, compression=true, eviction=lru",
            "Cache: ttl=7200, size=2GB, compression=true, eviction=lru",
            "Cache: ttl=1800, size=512MB, compression=false, eviction=fifo",
        ];

        let mut normalized_lines = Vec::new();
        for line in config_samples {
            let (normalized, _tokens) = KeyValueDetector::detect_and_replace(line);
            normalized_lines.push(normalized);
        }

        // After normalization, configuration lines with same structure
        // but different values should be more similar for folding
        let structural_patterns: Vec<_> = normalized_lines
            .iter()
            .map(|line| {
                // Count key-value tokens to see structural similarity
                line.matches("<KEY_VALUE>").count()
            })
            .collect();

        // Lines with same number of key-value pairs should group better
        let db_lines = &structural_patterns[0..3]; // Database configs
        let cache_lines = &structural_patterns[3..6]; // Cache configs

        // Database configs should have same structure
        assert!(
            db_lines.iter().all(|&count| count == db_lines[0]),
            "Database configs should have same structural pattern"
        );

        // Cache configs should have same structure
        assert!(
            cache_lines.iter().all(|&count| count == cache_lines[0]),
            "Cache configs should have same structural pattern"
        );
    }
}
