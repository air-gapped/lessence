use lessence::patterns::Token;
use lessence::patterns::bracket_context::BracketContextDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_bracketed_level_stays_literal() {
        let test_cases = vec![
            "[error] Something went wrong",
            "[info] Process completed",
            "[debug] Entering function",
            "[warn] Low memory condition",
            "[NOTICE] Low memory condition",
        ];

        for test_case in test_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);
            assert_eq!(
                result, test_case,
                "a bracketed level is the event's severity and stays literal, so an error and \
                 an info line are two events (lessence-bmp)"
            );
            assert!(tokens.is_empty(), "{test_case}: {tokens:?}");
        }
    }

    #[test]
    fn test_single_bracket_context_detection() {
        for test_case in [
            "[proxy] Something went wrong",
            "[upstream] Process completed",
        ] {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);
            assert!(result.starts_with("<BRACKET_CONTEXT> "), "{result}");
            assert_eq!(tokens.len(), 1, "{test_case}: {tokens:?}");
        }
    }

    #[test]
    fn test_multiple_bracket_context_detection() {
        let test_cases = vec![
            ("[error] [mod_jk] Something went wrong", "[error] ", 1),
            (
                "[info] [upstream] [cluster] Process completed",
                "[info] ",
                2,
            ),
            ("[debug] [ssl] [handshake] Entering function", "[debug] ", 2),
            (
                "[warn] [memory] [allocation] Low memory condition",
                "[warn] ",
                2,
            ),
        ];

        for (test_case, level, n_contexts) in test_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert!(
                result.starts_with(&format!("{level}<BRACKET_CONTEXT> ")),
                "the level leads the chain and stays; what follows folds as one context run: \
                 {test_case} -> {result}"
            );
            assert_eq!(tokens.len(), 1, "{test_case}: {tokens:?}");

            if let Token::BracketContext(contexts) = &tokens[0] {
                assert_eq!(contexts.len(), n_contexts, "{contexts:?}");
            } else {
                panic!("Expected BracketContext token, got: {:?}", tokens[0]);
            }
        }
    }

    #[test]
    fn test_microservices_envoy_logs() {
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

            assert!(
                !tokens.is_empty(),
                "Should detect bracket contexts in: {line}"
            );
        }

        let unique_bracket_patterns: std::collections::HashSet<_> = normalized_lines
            .iter()
            .map(|line| line.split("<BRACKET_CONTEXT>").collect::<Vec<_>>())
            .collect();

        assert!(
            unique_bracket_patterns.len() > 0,
            "Should detect bracket patterns"
        );
    }

    #[test]
    fn test_apache_mod_jk_logs() {
        let apache_logs = vec![
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:52:15 2005] [error] mod_ssl SSL handshake failed",
            "[Sun Dec 04 04:53:22 2005] [warn] mod_rewrite URL rewriting enabled",
        ];

        for line in apache_logs {
            let (result, tokens) = BracketContextDetector::detect_and_replace(line);

            assert_eq!(
                result, line,
                "the level stays on the line; level statistics come from the log-module \
                 detector and the briefing's own scan, not from this placeholder"
            );
            assert!(tokens.is_empty(), "{line}: {tokens:?}");
        }
    }

    #[test]
    fn test_systemd_journal_logs() {
        let systemd_logs = vec![
            (
                "systemd[1]: [info] [kernel] Starting network service",
                "systemd[1]: [info] <BRACKET_CONTEXT> Starting network service",
            ),
            (
                "systemd[1]: [error] [kernel] Failed to start application",
                "systemd[1]: [error] <BRACKET_CONTEXT> Failed to start application",
            ),
            (
                "kernel[0]: [warn] [memory] Low memory condition detected",
                "kernel[0]: [warn] <BRACKET_CONTEXT> Low memory condition detected",
            ),
        ];

        for (line, expected) in systemd_logs {
            let (result, tokens) = BracketContextDetector::detect_and_replace(line);
            assert_eq!(result, expected);
            assert_eq!(tokens.len(), 1, "{line}: {tokens:?}");
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
            "[proxy] Processing (failed) with {result: null}",
            "[info] [upstream] Connection to {host: example.com} established",
            "[debug] [ssl] Certificate [CN=*.example.com] validated",
        ];

        for test_case in mixed_cases {
            let (_, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert!(
                !tokens.is_empty(),
                "Should detect square bracket contexts in: {test_case}"
            );

            for token in tokens {
                if let Token::BracketContext(contexts) = token {
                    for context in contexts {
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

        let context_patterns: Vec<_> = normalized_lines
            .iter()
            .map(|line| line.matches("<BRACKET_CONTEXT>").count())
            .collect();

        for count in context_patterns {
            assert!(
                count > 0,
                "Each microservices log should have bracket contexts"
            );
        }

        let unique_patterns: std::collections::HashSet<_> = normalized_lines
            .iter()
            .map(|line| {
                line.replace(
                    |c: char| c.is_ascii_lowercase() || c.is_ascii_uppercase(),
                    "X",
                )
            })
            .collect();

        assert!(
            unique_patterns.len() < microservices_sample.len(),
            "Bracket normalization should reduce pattern variety for better compression"
        );
    }
}
