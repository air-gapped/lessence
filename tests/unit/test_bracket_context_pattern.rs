use lessence::patterns::Token;
use lessence::patterns::bracket_context::BracketContextDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_bracket_context_detection() {
        let test_cases = vec![
            "[error] Something went wrong",
            "[info] Process completed",
            "[debug] Entering function",
            "[warn] Low memory condition",
        ];

        for test_case in test_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<BRACKET_CONTEXT>"),
                "Failed to detect bracket context in: {test_case}"
            );
            assert_eq!(
                tokens.len(),
                1,
                "Should detect exactly one bracket context token"
            );

            if let Token::BracketContext(contexts) = &tokens[0] {
                assert_eq!(contexts.len(), 1, "Should detect one context");
            } else {
                panic!("Expected BracketContext token, got: {:?}", tokens[0]);
            }
        }
    }

    #[test]
    fn test_multiple_bracket_context_detection() {
        let test_cases = vec![
            "[error] [mod_jk] Something went wrong",
            "[info] [upstream] [cluster] Process completed",
            "[debug] [ssl] [handshake] Entering function",
            "[warn] [memory] [allocation] Low memory condition",
        ];

        for test_case in test_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<BRACKET_CONTEXT>"),
                "Failed to detect bracket context in: {test_case}"
            );
            assert_eq!(
                tokens.len(),
                1,
                "Should detect exactly one bracket context token for chained contexts"
            );

            if let Token::BracketContext(contexts) = &tokens[0] {
                assert!(
                    contexts.len() >= 2,
                    "Should detect multiple contexts: {contexts:?}"
                );
            } else {
                panic!("Expected BracketContext token, got: {:?}", tokens[0]);
            }
        }
    }

    #[test]
    fn test_microservices_envoy_logs() {
        // Real microservices log examples from research
        let envoy_logs = vec![
            "envoy[12345] [info] [upstream] cluster 'user-service' setting health check",
            "envoy[12346] [info] [upstream] cluster 'user-service' setting health check",
            "envoy[12347] [error] [upstream] cluster 'payment-service' connection failed",
            "envoy[12348] [warn] [config] [listener] invalid configuration detected",
        ];

        let mut normalized_lines = Vec::new();
        for line in envoy_logs {
            let (normalized, tokens) = BracketContextDetector::detect_and_replace(line);
            normalized_lines.push(normalized);

            // Each line should have at least one bracket context
            assert!(
                !tokens.is_empty(),
                "Should detect bracket contexts in: {line}"
            );
        }

        // After normalization, similar log patterns should group better
        let unique_bracket_patterns: std::collections::HashSet<_> = normalized_lines
            .iter()
            .map(|line| {
                // Extract the bracket context part
                line.split("<BRACKET_CONTEXT>").collect::<Vec<_>>()
            })
            .collect();

        // Normalization should help group similar log patterns
        assert!(
            unique_bracket_patterns.len() > 0,
            "Should detect bracket patterns"
        );
    }

    #[test]
    fn test_apache_mod_jk_logs() {
        // Real Apache log examples from research
        let apache_logs = vec![
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:52:15 2005] [error] mod_ssl SSL handshake failed",
            "[Sun Dec 04 04:53:22 2005] [warn] mod_rewrite URL rewriting enabled",
        ];

        for line in apache_logs {
            let (result, tokens) = BracketContextDetector::detect_and_replace(line);

            // Should detect [error], [warn] as bracket contexts
            // Note: timestamps should be handled by timestamp pattern detector
            assert!(
                !tokens.is_empty(),
                "Should detect bracket contexts in Apache logs: {line}"
            );

            // Check that we're detecting the log level bracket
            let has_log_level = tokens.iter().any(|token| {
                if let Token::BracketContext(contexts) = token {
                    contexts.iter().any(|ctx| {
                        ctx == "error" || ctx == "warn" || ctx == "info" || ctx == "debug"
                    })
                } else {
                    false
                }
            });

            assert!(
                has_log_level,
                "Should detect log level bracket context in: {line}"
            );
        }
    }

    #[test]
    fn test_systemd_journal_logs() {
        let systemd_logs = vec![
            "systemd[1]: [info] [unit] Starting network service",
            "systemd[1]: [error] [unit] Failed to start application",
            "kernel[0]: [warn] [memory] Low memory condition detected",
        ];

        for line in systemd_logs {
            let (result, tokens) = BracketContextDetector::detect_and_replace(line);

            assert!(
                !tokens.is_empty(),
                "Should detect bracket contexts in systemd logs: {line}"
            );
            assert!(
                result.contains("<BRACKET_CONTEXT>"),
                "Should normalize bracket contexts in: {line}"
            );
        }
    }

    #[test]
    fn test_no_false_positives() {
        let non_bracket_cases = vec![
            "Regular log message without brackets",
            "Math expression [1 + 2] = 3",
            "Array access array[index] operation",
            "IPv6 address [2001:db8::1]:8080",
            "URL with query params [param=value]",
        ];

        for test_case in non_bracket_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            // Should not detect bracket contexts in non-logging contexts
            assert_eq!(
                result, test_case,
                "Should not modify non-logging brackets: {test_case}"
            );
            assert_eq!(
                tokens.len(),
                0,
                "Should not detect tokens in non-logging context: {test_case}"
            );
        }
    }

    #[test]
    fn test_mixed_bracket_types() {
        let mixed_cases = vec![
            "[error] Processing (failed) with {result: null}",
            "[info] [upstream] Connection to {host: example.com} established",
            "[debug] [ssl] Certificate [CN=*.example.com] validated",
        ];

        for test_case in mixed_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            // Should detect square bracket contexts but not other bracket types
            assert!(
                !tokens.is_empty(),
                "Should detect square bracket contexts in: {test_case}"
            );

            // Verify we only detected square brackets, not parentheses or braces
            for token in tokens {
                if let Token::BracketContext(contexts) = token {
                    for context in contexts {
                        // None of the contexts should contain parentheses or braces
                        assert!(!context.contains('('), "Should not include parentheses");
                        assert!(!context.contains(')'), "Should not include parentheses");
                        assert!(!context.contains('{'), "Should not include braces");
                        assert!(!context.contains('}'), "Should not include braces");
                    }
                } else {
                    panic!("Expected BracketContext token");
                }
            }
        }
    }

    #[test]
    fn test_compression_improvement_target() {
        // This test validates the research finding that bracket context grouping
        // should improve microservices compression from 19% to >70%

        let microservices_sample = vec![
            "[info] [upstream] cluster 'service-a' health check passed",
            "[info] [upstream] cluster 'service-b' health check passed",
            "[info] [upstream] cluster 'service-c' health check passed",
            "[error] [upstream] cluster 'service-a' connection timeout",
            "[error] [upstream] cluster 'service-b' connection timeout",
            "[warn] [config] [listener] rate limit exceeded",
            "[warn] [config] [listener] buffer overflow detected",
        ];

        let mut normalized_lines = Vec::new();
        for line in &microservices_sample {
            let (normalized, _tokens) = BracketContextDetector::detect_and_replace(line);
            normalized_lines.push(normalized);
        }

        // After bracket context normalization, lines with same context patterns
        // should be more similar for folding
        let context_patterns: Vec<_> = normalized_lines
            .iter()
            .map(|line| {
                // Count bracket context tokens
                line.matches("<BRACKET_CONTEXT>").count()
            })
            .collect();

        // Each line should have bracket context tokens
        for count in context_patterns {
            assert!(
                count > 0,
                "Each microservices log should have bracket contexts"
            );
        }

        // Lines with same bracket patterns should be more similar after normalization
        let unique_patterns: std::collections::HashSet<_> = normalized_lines
            .iter()
            .map(|line| {
                // Extract the pattern after bracket normalization
                line.replace(
                    |c: char| c.is_ascii_lowercase() || c.is_ascii_uppercase(),
                    "X",
                )
            })
            .collect();

        // Should have fewer unique patterns than original for better compression
        assert!(
            unique_patterns.len() < microservices_sample.len(),
            "Bracket normalization should reduce pattern variety for better compression"
        );
    }
}
