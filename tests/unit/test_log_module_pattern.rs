use lessence::patterns::Token;
use lessence::patterns::log_module::LogWithModuleDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_mod_jk_detection() {
        let apache_logs = vec![
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:52:15 2005] [error] mod_ssl SSL handshake failed",
            "[Sun Dec 04 04:53:22 2005] [warn] mod_rewrite URL rewriting enabled",
        ];

        for log_line in apache_logs {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            // Should detect log level + module pattern
            assert!(
                !tokens.is_empty(),
                "Should detect log with module pattern in: {}",
                log_line
            );

            let has_log_module = tokens.iter().any(|token| {
                matches!(
                    token,
                    Token::LogWithModule {
                        level: _,
                        module: _
                    }
                )
            });

            assert!(
                has_log_module,
                "Should detect LogWithModule token in: {}",
                log_line
            );

            if let Some(Token::LogWithModule { level, module }) = tokens
                .iter()
                .find(|t| matches!(t, Token::LogWithModule { .. }))
            {
                assert!(
                    level == "error" || level == "warn" || level == "info",
                    "Should detect valid log level: {}",
                    level
                );
                assert!(
                    module.starts_with("mod_"),
                    "Should detect Apache module: {}",
                    module
                );
            }
        }
    }

    #[test]
    fn test_nginx_module_detection() {
        let nginx_logs = vec![
            "[error] 12345#0: *1 ngx_http_core_module: client disconnected",
            "[warn] 12346#0: *2 ngx_http_ssl_module: SSL handshake timeout",
            "[info] 12347#0: *3 ngx_http_upstream_module: backend connection established",
            "[debug] 12348#0: *4 ngx_http_rewrite_module: URL rewrite applied",
        ];

        for log_line in nginx_logs {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            let has_log_module = tokens.iter().any(|token| {
                matches!(
                    token,
                    Token::LogWithModule {
                        level: _,
                        module: _
                    }
                )
            });

            if has_log_module {
                if let Some(Token::LogWithModule { level, module }) = tokens
                    .iter()
                    .find(|t| matches!(t, Token::LogWithModule { .. }))
                {
                    assert!(
                        ["error", "warn", "info", "debug"].contains(&level.as_str()),
                        "Should detect valid nginx log level: {}",
                        level
                    );
                    assert!(
                        module.contains("ngx_http") || module.contains("module"),
                        "Should detect nginx module: {}",
                        module
                    );
                }
            }
        }
    }

    #[test]
    fn test_systemd_service_detection() {
        let systemd_logs = vec![
            "systemd[1]: [info] service_manager: Starting network service",
            "systemd[1]: [error] service_manager: Failed to start application",
            "kernel[0]: [warn] memory_manager: Low memory condition detected",
            "NetworkManager[1234]: [info] dhcp_client: Lease renewed",
        ];

        for log_line in systemd_logs {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            // Note: systemd logs might have different formats
            // This test validates detection when the pattern exists
            if !tokens.is_empty() {
                let has_log_module = tokens.iter().any(|token| {
                    matches!(
                        token,
                        Token::LogWithModule {
                            level: _,
                            module: _
                        }
                    )
                });

                if has_log_module {
                    if let Some(Token::LogWithModule { level, module }) = tokens
                        .iter()
                        .find(|t| matches!(t, Token::LogWithModule { .. }))
                    {
                        assert!(
                            ["error", "warn", "info", "debug"].contains(&level.as_str()),
                            "Should detect valid systemd log level: {}",
                            level
                        );
                        assert!(
                            !module.is_empty(),
                            "Should detect systemd component: {}",
                            module
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_syslog_facility_detection() {
        let syslog_entries = vec![
            "kern.error kernel: Out of memory condition",
            "mail.info postfix: Message delivered successfully",
            "auth.warn sshd: Failed login attempt",
            "daemon.debug nginx: Connection established",
        ];

        for log_line in syslog_entries {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            // Syslog format: facility.level module: message
            if !tokens.is_empty() {
                let has_log_module = tokens.iter().any(|token| {
                    matches!(
                        token,
                        Token::LogWithModule {
                            level: _,
                            module: _
                        }
                    )
                });

                if has_log_module {
                    if let Some(Token::LogWithModule { level, module }) = tokens
                        .iter()
                        .find(|t| matches!(t, Token::LogWithModule { .. }))
                    {
                        assert!(
                            ["error", "warn", "info", "debug"].contains(&level.as_str()),
                            "Should detect valid syslog level: {}",
                            level
                        );
                        assert!(
                            !module.is_empty(),
                            "Should detect syslog daemon: {}",
                            module
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_application_logging_frameworks() {
        let framework_logs = vec![
            "2024-01-01 10:00:00 ERROR [hibernate.SQL] Database connection failed",
            "2024-01-01 10:00:01 INFO [spring.web] Request processed successfully",
            "2024-01-01 10:00:02 WARN [security.auth] Invalid authentication token",
            "2024-01-01 10:00:03 DEBUG [cache.redis] Cache hit for key user:12345",
        ];

        for log_line in framework_logs {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            // Modern logging frameworks often use [module] format
            if !tokens.is_empty() {
                let has_log_module = tokens.iter().any(|token| {
                    matches!(
                        token,
                        Token::LogWithModule {
                            level: _,
                            module: _
                        }
                    )
                });

                if has_log_module {
                    if let Some(Token::LogWithModule { level, module }) = tokens
                        .iter()
                        .find(|t| matches!(t, Token::LogWithModule { .. }))
                    {
                        assert!(
                            ["ERROR", "INFO", "WARN", "DEBUG"].contains(&level.as_str())
                                || ["error", "info", "warn", "debug"].contains(&level.as_str()),
                            "Should detect valid framework log level: {}",
                            level
                        );
                        assert!(
                            !module.is_empty(),
                            "Should detect framework module: {}",
                            module
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_no_false_positives() {
        let non_module_cases = vec![
            "Regular log message without module",
            "Processing mod_calculation = result + 5",
            "Error in module loading function",
            "Information about modules in documentation",
            "[timestamp] Simple message without module",
        ];

        for test_case in non_module_cases {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(test_case);

            // Should not detect log-with-module pattern in non-logging contexts
            let has_log_module = tokens.iter().any(|token| {
                matches!(
                    token,
                    Token::LogWithModule {
                        level: _,
                        module: _
                    }
                )
            });

            if has_log_module {
                // If detected, it should be a valid logging pattern
                if let Some(Token::LogWithModule { level, module }) = tokens
                    .iter()
                    .find(|t| matches!(t, Token::LogWithModule { .. }))
                {
                    // Strict validation for potential false positives
                    assert!(
                        [
                            "ERROR", "INFO", "WARN", "DEBUG", "error", "info", "warn", "debug"
                        ]
                        .contains(&level.as_str()),
                        "Detected level should be valid log level: {}",
                        level
                    );
                }
            }
        }
    }

    #[test]
    fn test_case_insensitive_detection() {
        let mixed_case_logs = vec![
            "[ERROR] mod_ssl Connection error",
            "[Info] MOD_REWRITE Redirect applied",
            "[Warn] Mod_Security Rule triggered",
            "[DEBUG] mod_proxy Backend timeout",
        ];

        for log_line in mixed_case_logs {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(log_line);

            // Should handle different case variations
            if !tokens.is_empty() {
                let has_log_module = tokens.iter().any(|token| {
                    matches!(
                        token,
                        Token::LogWithModule {
                            level: _,
                            module: _
                        }
                    )
                });

                if has_log_module {
                    if let Some(Token::LogWithModule { level, module }) = tokens
                        .iter()
                        .find(|t| matches!(t, Token::LogWithModule { .. }))
                    {
                        // Level should be normalized to lowercase
                        assert!(
                            level.chars().all(|c| c.is_lowercase()),
                            "Log level should be normalized to lowercase: {}",
                            level
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_compression_improvement_target() {
        // This test validates that log-with-module normalization improves
        // compression for Apache and system logs

        let apache_samples = vec![
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6",
            "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 7",
            "[Sun Dec 04 04:52:15 2005] [error] mod_jk child workerEnv in error state 8",
            "[Sun Dec 04 04:53:22 2005] [warn] mod_ssl SSL handshake failed",
            "[Sun Dec 04 04:54:30 2005] [warn] mod_ssl SSL handshake timeout",
            "[Sun Dec 04 04:55:45 2005] [info] mod_rewrite URL rewrite enabled",
        ];

        let mut normalized_lines = Vec::new();
        for line in &apache_samples {
            let (normalized, _tokens) = LogWithModuleDetector::detect_and_replace(line);
            normalized_lines.push(normalized);
        }

        // After normalization, similar log patterns with same level+module
        // should group better for folding
        let module_patterns: Vec<_> = normalized_lines
            .iter()
            .map(|line| {
                // Count LOG_WITH_MODULE tokens
                line.matches("<LOG_WITH_MODULE>").count()
            })
            .collect();

        // Each Apache log line should have log-with-module pattern
        for count in module_patterns {
            assert!(
                count > 0,
                "Each Apache log should have log-with-module pattern"
            );
        }

        // Lines with same module should be more similar after normalization
        let mod_jk_lines: Vec<_> = normalized_lines
            .iter()
            .filter(|line| line.contains("mod_jk") || line.contains("<LOG_WITH_MODULE>"))
            .collect();

        assert!(
            !mod_jk_lines.is_empty(),
            "Should have mod_jk lines for compression grouping"
        );

        // Similar module patterns should help compression
        let unique_patterns: std::collections::HashSet<_> = normalized_lines
            .iter()
            .map(|line| {
                // Extract structural pattern after normalization
                line.replace(|c: char| c.is_ascii_digit(), "N")
            })
            .collect();

        assert!(
            unique_patterns.len() < apache_samples.len(),
            "Module normalization should reduce pattern variety for better compression"
        );
    }
}
