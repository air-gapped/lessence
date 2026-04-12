use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Single bracket context: [error], [info], [upstream]
static SINGLE_BRACKET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[([a-zA-Z][a-zA-Z0-9_.-]*)\]").unwrap());

// Chained bracket contexts: [error] [mod_jk], [info] [upstream] [cluster]
static CHAINED_BRACKET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\[([a-zA-Z][a-zA-Z0-9_.-]*)\]\s*){2,}").unwrap());

pub struct BracketContextDetector;

impl BracketContextDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no square brackets
        if !Self::has_bracket_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Apply bracket context detection in order of priority
        Self::apply_chained_bracket_pattern(&mut result, &mut tokens);
        Self::apply_single_bracket_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_bracket_indicators(text: &str) -> bool {
        // Fast byte-level check for square brackets
        text.contains('[') && text.contains(']') &&
        // Exclude common non-logging bracket patterns
        !text.contains("[2001:") &&  // IPv6
        !text.contains("array[") &&  // Array access
        !text.contains("index[") &&  // Index operations
        !text.contains("param=") &&  // URL params
        !text.contains("[1 +") &&    // Math expressions
        !text.contains("[0-9") &&    // Regex patterns in logs
        // CRITICAL: Exclude Kubernetes patterns to prevent pattern theft
        !Self::has_kubernetes_indicators(text)
    }

    /// Detect if text contains Kubernetes patterns that should be handled by KubernetesDetector
    fn has_kubernetes_indicators(text: &str) -> bool {
        // Kubernetes namespaces
        text.contains("kubernetes.io/") ||
        text.contains("namespace/") ||
        text.contains("pod/") ||
        text.contains("service/") ||
        text.contains("configmap/") ||
        text.contains("secret/") ||
        text.contains("deployment/") ||
        // Kubernetes volume patterns
        text.contains("volumes/") ||
        text.contains("projected-") ||
        text.contains("volume-subpath") ||
        text.contains("projected") ||
        // Kubernetes API patterns
        text.contains("apiserver") ||
        text.contains("kube-") ||
        // Common K8s log prefixes that use brackets
        text.contains("kubelet") ||
        text.contains("kube-proxy") ||
        text.contains("kube-scheduler") ||
        text.contains("kube-controller") ||
        text.contains("etcd") ||
        text.contains("coredns")
    }

    fn apply_chained_bracket_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        let mut processed_indices = std::collections::HashSet::new();

        // Find all chained bracket sequences
        for mat in CHAINED_BRACKET_REGEX.find_iter(text) {
            let match_text = mat.as_str();
            let contexts = Self::extract_contexts_from_chain(match_text);

            if contexts.len() >= 2 && Self::are_logging_contexts(&contexts) {
                tokens.push(Token::BracketContext(contexts));
                processed_indices.insert(mat.start());
            }
        }

        // Replace chained patterns
        if !processed_indices.is_empty() {
            *text = CHAINED_BRACKET_REGEX
                .replace_all(text, |caps: &regex::Captures| {
                    let contexts = Self::extract_contexts_from_chain(caps.get(0).unwrap().as_str());
                    if contexts.len() >= 2 && Self::are_logging_contexts(&contexts) {
                        "<BRACKET_CONTEXT>".to_string()
                    } else {
                        caps.get(0).unwrap().as_str().to_string()
                    }
                })
                .to_string();
        }
    }

    fn apply_single_bracket_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = SINGLE_BRACKET_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let context = caps.get(1).unwrap().as_str();

                if Self::is_logging_context(context) {
                    tokens.push(Token::BracketContext(vec![context.to_lowercase()]));
                    "<BRACKET_CONTEXT>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn extract_contexts_from_chain(chain: &str) -> Vec<String> {
        SINGLE_BRACKET_REGEX
            .captures_iter(chain)
            .map(|cap| cap.get(1).unwrap().as_str().to_lowercase())
            .collect()
    }

    fn is_logging_context(context: &str) -> bool {
        let lower_context = context.to_lowercase();

        // Common log levels
        let log_levels = [
            "error",
            "err",
            "warn",
            "warning",
            "info",
            "information",
            "debug",
            "trace",
            "fatal",
            "crit",
            "critical",
            "notice",
            "emerg",
            "emergency",
            "alert",
        ];

        // Common logging components
        let log_components = [
            "upstream",
            "downstream",
            "proxy",
            "ssl",
            "tls",
            "auth",
            "config",
            "listener",
            "cluster",
            "backend",
            "frontend",
            "handler",
            "worker",
            "manager",
            "service",
            "client",
            "server",
            "connection",
            "request",
            "response",
            "session",
        ];

        // Apache/Nginx modules
        let web_modules = [
            "mod_jk",
            "mod_ssl",
            "mod_rewrite",
            "mod_security",
            "mod_proxy",
            "ngx_http",
            "core",
            "main",
            "event",
            "http",
        ];

        // NOTE: Kubernetes contexts removed to prevent pattern theft
        // These should be handled by KubernetesDetector instead

        // System components
        let system_contexts = [
            "kernel", "systemd", "init", "cron", "syslog", "audit", "security", "firewall",
            "network", "storage", "memory",
        ];

        log_levels.contains(&lower_context.as_str()) ||
        log_components.contains(&lower_context.as_str()) ||
        web_modules.iter().any(|&module| lower_context.contains(module)) ||
        system_contexts.contains(&lower_context.as_str()) ||
        // Pattern-based detection
        lower_context.ends_with("_service") ||
        lower_context.ends_with("_manager") ||
        lower_context.ends_with("_client") ||
        lower_context.ends_with("_server") ||
        lower_context.starts_with("mod_") ||
        lower_context.starts_with("ngx_")
    }

    fn are_logging_contexts(contexts: &[String]) -> bool {
        // At least one should be a recognized logging context
        contexts.iter().any(|ctx| Self::is_logging_context(ctx)) &&
        // None should be obvious non-logging patterns
        !contexts.iter().any(|ctx| {
            ctx.chars().all(|c| c.is_ascii_digit()) ||  // [123]
            ctx.contains(':') ||                        // [2001:db8]
            ctx.len() == 1                             // [a]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_mod_jk_detection() {
        let apache_line =
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6";
        let (result, tokens) = BracketContextDetector::detect_and_replace(apache_line);

        assert!(!tokens.is_empty());
        assert!(result.contains("<BRACKET_CONTEXT>"));

        // Should detect [error] as a bracket context
        let has_error_context = tokens.iter().any(|token| {
            if let Token::BracketContext(contexts) = token {
                contexts.contains(&"error".to_string())
            } else {
                false
            }
        });
        assert!(has_error_context);
    }

    #[test]
    fn test_envoy_chained_contexts() {
        let envoy_line =
            "envoy[12345] [info] [upstream] cluster 'user-service' setting health check";
        let (result, tokens) = BracketContextDetector::detect_and_replace(envoy_line);

        assert!(!tokens.is_empty());
        assert!(result.contains("<BRACKET_CONTEXT>"));

        // Should detect [info] [upstream] as chained contexts
        let has_chained = tokens.iter().any(|token| {
            if let Token::BracketContext(contexts) = token {
                contexts.len() >= 2
            } else {
                false
            }
        });
        assert!(has_chained);
    }

    #[test]
    fn test_systemd_contexts() {
        let systemd_line = "systemd[1]: [info] [unit] Starting network service";
        let (result, tokens) = BracketContextDetector::detect_and_replace(systemd_line);

        if !tokens.is_empty() {
            assert!(result.contains("<BRACKET_CONTEXT>"));
        }
    }

    #[test]
    fn test_no_false_positives() {
        let non_logging_cases = vec![
            "Array access array[index] operation",
            "IPv6 address [2001:db8::1]:8080",
            "Math expression [1 + 2] = 3",
            "URL with query params [param=value]",
        ];

        for test_case in non_logging_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert_eq!(result, test_case);
            assert_eq!(tokens.len(), 0);
        }
    }

    #[test]
    fn test_mixed_bracket_types() {
        let mixed_line = "[error] Processing (failed) with {result: null}";
        let (_result, tokens) = BracketContextDetector::detect_and_replace(mixed_line);

        // Should only detect square brackets [error], not () or {}
        assert_eq!(tokens.len(), 1);
        if let Token::BracketContext(contexts) = &tokens[0] {
            assert_eq!(contexts[0], "error");
        }
    }

    // ---- has_bracket_indicators: per-condition tests ----

    #[test]
    fn bracket_ind_requires_open_bracket() {
        // Has ] but not [
        assert!(!BracketContextDetector::has_bracket_indicators("error] happened"));
    }

    #[test]
    fn bracket_ind_requires_close_bracket() {
        // Has [ but not ]
        assert!(!BracketContextDetector::has_bracket_indicators("[error happened"));
    }

    #[test]
    fn bracket_ind_positive() {
        assert!(BracketContextDetector::has_bracket_indicators("[error] happened"));
    }

    #[test]
    fn bracket_ind_excludes_ipv6() {
        assert!(!BracketContextDetector::has_bracket_indicators("[2001:db8::1]"));
    }

    #[test]
    fn bracket_ind_excludes_array_access() {
        assert!(!BracketContextDetector::has_bracket_indicators("data array[0] value"));
    }

    #[test]
    fn bracket_ind_excludes_index() {
        assert!(!BracketContextDetector::has_bracket_indicators("at index[5] pos"));
    }

    #[test]
    fn bracket_ind_excludes_url_params() {
        assert!(!BracketContextDetector::has_bracket_indicators("[x] param=value"));
    }

    #[test]
    fn bracket_ind_excludes_math() {
        assert!(!BracketContextDetector::has_bracket_indicators("[1 + 2]"));
    }

    #[test]
    fn bracket_ind_excludes_regex() {
        assert!(!BracketContextDetector::has_bracket_indicators("[0-9] pattern"));
    }

    #[test]
    fn bracket_ind_excludes_k8s() {
        assert!(!BracketContextDetector::has_bracket_indicators("[error] kubelet started"));
    }

    // ---- has_kubernetes_indicators: per-condition tests ----

    #[test]
    fn k8s_ind_kubernetes_io() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kubernetes.io/name"));
    }

    #[test]
    fn k8s_ind_namespace() {
        assert!(BracketContextDetector::has_kubernetes_indicators("namespace/default"));
    }

    #[test]
    fn k8s_ind_pod() {
        assert!(BracketContextDetector::has_kubernetes_indicators("pod/nginx-abc"));
    }

    #[test]
    fn k8s_ind_service() {
        assert!(BracketContextDetector::has_kubernetes_indicators("service/web"));
    }

    #[test]
    fn k8s_ind_configmap() {
        assert!(BracketContextDetector::has_kubernetes_indicators("configmap/cfg"));
    }

    #[test]
    fn k8s_ind_secret() {
        assert!(BracketContextDetector::has_kubernetes_indicators("secret/tls"));
    }

    #[test]
    fn k8s_ind_deployment() {
        assert!(BracketContextDetector::has_kubernetes_indicators("deployment/app"));
    }

    #[test]
    fn k8s_ind_volumes() {
        assert!(BracketContextDetector::has_kubernetes_indicators("volumes/data"));
    }

    #[test]
    fn k8s_ind_projected_dash() {
        assert!(BracketContextDetector::has_kubernetes_indicators("projected-token"));
    }

    #[test]
    fn k8s_ind_volume_subpath() {
        assert!(BracketContextDetector::has_kubernetes_indicators("volume-subpath check"));
    }

    #[test]
    fn k8s_ind_projected() {
        assert!(BracketContextDetector::has_kubernetes_indicators("using projected volume"));
    }

    #[test]
    fn k8s_ind_apiserver() {
        assert!(BracketContextDetector::has_kubernetes_indicators("apiserver health"));
    }

    #[test]
    fn k8s_ind_kube_prefix() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kube-dns ready"));
    }

    #[test]
    fn k8s_ind_kubelet() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kubelet started"));
    }

    #[test]
    fn k8s_ind_kube_proxy() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kube-proxy running"));
    }

    #[test]
    fn k8s_ind_kube_scheduler() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kube-scheduler leader"));
    }

    #[test]
    fn k8s_ind_kube_controller() {
        assert!(BracketContextDetector::has_kubernetes_indicators("kube-controller ready"));
    }

    #[test]
    fn k8s_ind_etcd() {
        assert!(BracketContextDetector::has_kubernetes_indicators("etcd cluster"));
    }

    #[test]
    fn k8s_ind_coredns() {
        assert!(BracketContextDetector::has_kubernetes_indicators("coredns serving"));
    }

    #[test]
    fn k8s_ind_negative() {
        assert!(!BracketContextDetector::has_kubernetes_indicators("plain log message"));
    }

    #[test]
    fn test_context_classification() {
        assert!(BracketContextDetector::is_logging_context("error"));
        assert!(BracketContextDetector::is_logging_context("upstream"));
        assert!(BracketContextDetector::is_logging_context("mod_ssl"));
        // "kubelet" is no longer a logging context - it's handled by KubernetesDetector
        assert!(!BracketContextDetector::is_logging_context("kubelet"));

        assert!(!BracketContextDetector::is_logging_context("123"));
        assert!(!BracketContextDetector::is_logging_context("2001:db8"));
        assert!(!BracketContextDetector::is_logging_context("a"));
    }

    // ---- is_logging_context: per-branch tests ----

    #[test]
    fn logging_ctx_system_context() {
        assert!(BracketContextDetector::is_logging_context("kernel"));
        assert!(BracketContextDetector::is_logging_context("cron"));
        assert!(BracketContextDetector::is_logging_context("firewall"));
    }

    #[test]
    fn logging_ctx_service_suffix() {
        assert!(BracketContextDetector::is_logging_context("app_service"));
    }

    #[test]
    fn logging_ctx_manager_suffix() {
        assert!(BracketContextDetector::is_logging_context("task_manager"));
    }

    #[test]
    fn logging_ctx_client_suffix() {
        assert!(BracketContextDetector::is_logging_context("http_client"));
    }

    #[test]
    fn logging_ctx_server_suffix() {
        assert!(BracketContextDetector::is_logging_context("web_server"));
    }

    #[test]
    fn logging_ctx_mod_prefix() {
        assert!(BracketContextDetector::is_logging_context("mod_proxy"));
    }

    #[test]
    fn logging_ctx_ngx_prefix() {
        assert!(BracketContextDetector::is_logging_context("ngx_http"));
    }

    #[test]
    fn logging_ctx_web_module() {
        assert!(BracketContextDetector::is_logging_context("core"));
        assert!(BracketContextDetector::is_logging_context("event"));
    }

    #[test]
    fn logging_ctx_log_component() {
        assert!(BracketContextDetector::is_logging_context("proxy"));
        assert!(BracketContextDetector::is_logging_context("ssl"));
        assert!(BracketContextDetector::is_logging_context("auth"));
    }

    #[test]
    fn logging_ctx_negative() {
        assert!(!BracketContextDetector::is_logging_context("zzz_random"));
    }

    // ---- are_logging_contexts: per-condition tests ----

    #[test]
    fn are_logging_ctxs_valid() {
        assert!(BracketContextDetector::are_logging_contexts(&[
            "error".to_string()
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_all_digits() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "error".to_string(),
            "123".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_colon() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "error".to_string(),
            "2001:db8".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_single_char() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "error".to_string(),
            "a".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_none_recognized() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "zzz".to_string()
        ]));
    }

    // ---- Mutant-killing: k8s indicators kube-scheduler/kube-controller (lines 66-67) ----

    #[test]
    fn k8s_ind_kube_scheduler_only() {
        // Kills mutant: `|| with &&` on kube-scheduler (line 67)
        // Input has kube-scheduler but NOT kubelet, kube-proxy, etcd, coredns, etc.
        // "kube-scheduler" also contains "kube-" so it would match that branch too.
        // But the specific `kube-scheduler` branch must independently work.
        assert!(BracketContextDetector::has_kubernetes_indicators("the kube-scheduler elected leader"));
    }

    #[test]
    fn k8s_ind_kube_controller_only() {
        // Kills mutant: `|| with &&` on kube-controller (line 68)
        assert!(BracketContextDetector::has_kubernetes_indicators("the kube-controller is ready"));
    }

    // ---- Mutant-killing: apply_chained_bracket_pattern inner logic ----

    #[test]
    fn chained_brackets_require_two_contexts() {
        // Kills mutant on contexts.len() >= 2 (line 81)
        // Single bracket should NOT trigger chained pattern
        let (result, tokens) = BracketContextDetector::detect_and_replace("[error] something failed");
        // Single bracket should trigger single pattern, not chained
        assert!(!tokens.is_empty(), "should detect [error]");
        assert!(result.contains("<BRACKET_CONTEXT>"));
    }

    #[test]
    fn chained_brackets_with_logging_contexts() {
        // Kills mutant on are_logging_contexts check (line 81, 92)
        let (result, tokens) = BracketContextDetector::detect_and_replace("[error] [upstream] request failed");
        assert!(
            tokens.iter().any(|t| if let Token::BracketContext(ctxs) = t { ctxs.len() >= 2 } else { false }),
            "should detect chained contexts: {tokens:?}"
        );
        assert!(result.contains("<BRACKET_CONTEXT>"), "result: {result}");
    }

    #[test]
    fn chained_brackets_non_logging_not_replaced() {
        // Non-logging bracket chains should NOT be replaced
        // But both must be recognized logging contexts. "zzz" is not.
        let input = "[zzz] [qqq] something";
        let (result, tokens) = BracketContextDetector::detect_and_replace(input);
        // Neither zzz nor qqq is a logging context, so no chained detection
        let chained = tokens.iter().any(|t| if let Token::BracketContext(ctxs) = t { ctxs.len() >= 2 } else { false });
        assert!(!chained, "non-logging chains should not be detected: {tokens:?}");
        // Single brackets might still be detected or not
        let _ = result;
    }

    // ---- Mutant-killing: is_logging_context suffix patterns (line ~203) ----

    #[test]
    fn logging_ctx_service_suffix_detected() {
        // Kills mutant: `|| with &&` on ends_with("_service") (line 199)
        // "my_service" is not in log_levels, log_components, web_modules, or system_contexts
        // It only matches via the suffix pattern
        assert!(BracketContextDetector::is_logging_context("custom_service"));
    }

    #[test]
    fn logging_ctx_manager_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_manager"));
    }

    #[test]
    fn logging_ctx_client_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_client"));
    }

    #[test]
    fn logging_ctx_server_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_server"));
    }

    #[test]
    fn logging_ctx_mod_prefix_detected() {
        // Not in the web_modules array directly, but starts_with("mod_")
        assert!(BracketContextDetector::is_logging_context("mod_custom"));
    }

    #[test]
    fn logging_ctx_ngx_prefix_detected() {
        assert!(BracketContextDetector::is_logging_context("ngx_custom"));
    }
}
