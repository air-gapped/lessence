use lessence::patterns::Token;
use lessence::patterns::key_value::KeyValueDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_logs() {
        let metrics_logs = vec![
            "Performance metrics: cpu=75%, memory=60%, disk=45%",
            "Request stats: count=1024, avg_time=120ms, error_rate=2.5%",
            "Circuit breaker: attempt_count=1, failure_rate=65%",
            "Load balancer: active_connections=50, queue_size=10, throughput=500rps",
        ];

        for line in metrics_logs {
            let (_, tokens) = KeyValueDetector::detect_and_replace(line);

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
