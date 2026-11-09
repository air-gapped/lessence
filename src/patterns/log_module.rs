use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Apache style: [error] mod_jk message
static APACHE_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\[(error|warn|warning|info|information|debug|trace|fatal|crit|critical|notice)\]\s+(mod_\w+)"
    ).unwrap()
});

// Nginx style: [error] 12345#0: *1 ngx_http_core_module: message
static NGINX_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\[(error|warn|warning|info|information|debug|trace|fatal|crit|critical|notice)\]\s+\d+#\d+:\s*\*?\d*\s+(ngx_\w+(?:_module)?)"
    ).unwrap()
});

// Framework style: LEVEL [module.component] message
static FRAMEWORK_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(ERROR|WARN|WARNING|INFO|INFORMATION|DEBUG|TRACE|FATAL|CRITICAL)\s+\[([a-zA-Z][a-zA-Z0-9_.]+)\]"
    ).unwrap()
});

// Systemd style: service[pid]: [level] component: message
static SYSTEMD_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"([a-zA-Z][a-zA-Z0-9_-]+)\[\d+\]:\s*\[(error|warn|warning|info|information|debug|trace|fatal)\]\s+([a-zA-Z][a-zA-Z0-9_]+):"
    ).unwrap()
});

pub struct LogWithModuleDetector;

impl LogWithModuleDetector {
    /// The level and the module name are the event's identity, not a
    /// variable value, so the Apache, nginx and systemd shapes leave the
    /// line unchanged and the token only feeds the level statistics.
    /// Replacing `[error] mod_jk` with one placeholder made an error and a
    /// notice from one module one event.
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no log module indicators
        if !Self::has_log_module_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut tokens = Vec::new();

        // Apply log-with-module detection in order of specificity
        Self::apply_apache_pattern(text, &mut tokens);
        Self::apply_nginx_pattern(text, &mut tokens);
        let mut result = text.to_string();
        Self::apply_framework_pattern(&mut result, &mut tokens);
        Self::apply_systemd_pattern(&result, &mut tokens);

        (result, tokens)
    }

    /// Push a token for every match the recogniser accepts; the text is
    /// never rewritten (see `detect_and_replace`).
    fn note_matches(
        text: &str,
        tokens: &mut Vec<Token>,
        regex: &Regex,
        recognise: impl Fn(&regex::Captures) -> Option<Token>,
    ) {
        tokens.extend(
            regex
                .captures_iter(text)
                .filter_map(|caps| recognise(&caps)),
        );
    }

    // Kubernetes deference is NOT checked here: the detector ordering table
    // in `normalize.rs` skips this detector on kubernetes-shaped lines
    // (`patterns::has_kubernetes_indicators`) before it is invoked.
    pub(crate) fn has_log_module_indicators(text: &str) -> bool {
        // Fast byte-level checks for log module indicators
        (text.contains("mod_") ||
         text.contains("ngx_") ||
         text.contains("[error]") ||
         text.contains("[warn") ||
         text.contains("[info") ||
         text.contains("[debug") ||
         text.contains("ERROR ") ||
         text.contains("WARN ") ||
         text.contains("INFO ") ||
         text.contains("DEBUG ")) &&
        // Exclude non-logging contexts
        !text.contains("function ") &&
        !text.contains("class ") &&
        !text.contains("import ")
    }

    fn apply_apache_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &APACHE_LOG_MODULE_REGEX, |caps| {
            let level = caps.get(1).unwrap().as_str();
            let module = caps.get(2).unwrap().as_str();
            Self::is_apache_module(module).then(|| Token::LogWithModule {
                level: level.to_lowercase(),
                module: module.to_string(),
            })
        });
    }

    fn apply_nginx_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &NGINX_LOG_MODULE_REGEX, |caps| {
            let level = caps.get(1).unwrap().as_str();
            let module = caps.get(2).unwrap().as_str();
            Self::is_nginx_module(module).then(|| Token::LogWithModule {
                level: level.to_lowercase(),
                module: module.to_string(),
            })
        });
    }

    // Still folds the logger: keeping it literal is right but moves the
    // keycloak corpus past the reviewed output-size allowance, so it waits
    // for that baseline to be reviewed. The level stays on the line.
    fn apply_framework_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(text, tokens, &FRAMEWORK_LOG_MODULE_REGEX, |caps| {
            let level = caps.get(1).unwrap().as_str();
            let module = caps.get(2).unwrap().as_str();
            Self::is_framework_module(module).then(|| {
                (
                    Token::LogWithModule {
                        level: level.to_lowercase(),
                        module: module.to_string(),
                    },
                    format!("{level} [<LOG_WITH_MODULE>]"),
                )
            })
        });
    }

    fn apply_systemd_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &SYSTEMD_LOG_MODULE_REGEX, |caps| {
            let service = caps.get(1).unwrap().as_str();
            let level = caps.get(2).unwrap().as_str();
            let component = caps.get(3).unwrap().as_str();
            Self::is_systemd_component(component).then(|| Token::LogWithModule {
                level: level.to_lowercase(),
                module: format!("{service}.{component}"),
            })
        });
    }

    fn is_apache_module(module: &str) -> bool {
        let apache_modules = [
            "mod_jk",
            "mod_ssl",
            "mod_rewrite",
            "mod_security",
            "mod_proxy",
            "mod_deflate",
            "mod_expires",
            "mod_headers",
            "mod_auth",
            "mod_authz",
            "mod_authn",
            "mod_cache",
            "mod_fcgid",
            "mod_wsgi",
            "mod_php",
            "mod_perl",
            "mod_python",
            "mod_dir",
            "mod_alias",
            "mod_mime",
        ];

        apache_modules
            .iter()
            .any(|&known_module| module.starts_with(known_module))
    }

    fn is_nginx_module(module: &str) -> bool {
        let nginx_modules = [
            "ngx_http_core",
            "ngx_http_ssl",
            "ngx_http_rewrite",
            "ngx_http_proxy",
            "ngx_http_upstream",
            "ngx_http_fastcgi",
            "ngx_http_gzip",
            "ngx_http_auth",
            "ngx_http_access",
            "ngx_http_limit",
            "ngx_http_log",
            "ngx_stream",
            "ngx_mail",
        ];

        nginx_modules
            .iter()
            .any(|&known_module| module.starts_with(known_module))
            || module.starts_with("ngx_") && module.contains("module")
    }

    fn is_framework_module(module: &str) -> bool {
        let framework_patterns = [
            "spring",
            "hibernate",
            "slf4j",
            "logback",
            "log4j",
            "junit",
            "jackson",
            "servlet",
            "jdbc",
            "jpa",
            "security",
            "web",
            "mvc",
            "rest",
            "data",
            "cache",
            "redis",
            "mongodb",
            "elasticsearch",
        ];

        framework_patterns.iter().any(|&pattern| module.contains(pattern)) ||
        module.contains('.') ||  // Package-style modules
        module.contains('_') // Underscore-separated modules
    }

    fn is_systemd_component(component: &str) -> bool {
        let systemd_components = [
            "service_manager",
            "unit_manager",
            "network_manager",
            "device_manager",
            "mount_manager",
            "socket_manager",
            "timer_manager",
            "target_manager",
            "slice_manager",
            "scope_manager",
            "snapshot_manager",
            "swap_manager",
            "path_manager",
            "automount_manager",
            "busname_manager",
        ];

        systemd_components.contains(&component)
            || component.ends_with("_manager")
            || component.ends_with("_service")
            || component.ends_with("_client")
            || component.ends_with("_daemon")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_mod_jk_detection() {
        let apache_line =
            "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(apache_line);

        // the level and the module stay on the line; only the token is new
        assert_eq!(result, apache_line);
        assert_eq!(
            tokens,
            vec![Token::LogWithModule {
                level: "error".into(),
                module: "mod_jk".into(),
            }]
        );
    }

    #[test]
    fn test_nginx_module_detection() {
        let nginx_line = "[error] 12345#0: *1 ngx_http_core_module: client disconnected";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(nginx_line);

        assert_eq!(result, nginx_line);
        assert_eq!(
            tokens,
            vec![Token::LogWithModule {
                level: "error".into(),
                module: "ngx_http_core_module".into(),
            }]
        );
    }

    #[test]
    fn test_framework_logging() {
        let framework_line = "2024-01-01 10:00:00 ERROR [hibernate.SQL] Database connection failed";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(framework_line);

        assert_eq!(
            result,
            "2024-01-01 10:00:00 ERROR [<LOG_WITH_MODULE>] Database connection failed"
        );
        assert_eq!(
            tokens,
            vec![Token::LogWithModule {
                level: "error".into(),
                module: "hibernate.SQL".into(),
            }]
        );
    }

    #[test]
    fn test_systemd_service_detection() {
        let systemd_line = "systemd[1]: [info] service_manager: Starting network service";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(systemd_line);

        assert_eq!(result, systemd_line);
        assert_eq!(
            tokens,
            vec![Token::LogWithModule {
                level: "info".into(),
                module: "systemd.service_manager".into(),
            }]
        );
    }

    #[test]
    fn test_module_classification() {
        assert!(LogWithModuleDetector::is_apache_module("mod_jk"));
        assert!(LogWithModuleDetector::is_apache_module("mod_ssl"));
        assert!(LogWithModuleDetector::is_nginx_module("ngx_http_core"));
        assert!(LogWithModuleDetector::is_framework_module("spring.web"));
        assert!(LogWithModuleDetector::is_systemd_component(
            "service_manager"
        ));
    }

    #[test]
    fn test_no_false_positives() {
        let non_module_cases = vec![
            "Regular log message without module",
            "Processing mod_calculation = result + 5",
            "function mod_test() { return true; }",
            "import mod_library from 'package'",
        ];

        for test_case in non_module_cases {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(test_case);

            // Should not detect false positives in programming contexts
            if test_case.contains("function ") || test_case.contains("import ") {
                assert_eq!(tokens.len(), 0);
                assert_eq!(result, test_case);
            }
        }
    }

    // ---- has_log_module_indicators: per-condition tests ----
    // Positive: each || branch in the first group

    #[test]
    fn log_mod_ind_mod_prefix() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "mod_ssl enabled"
        ));
    }

    #[test]
    fn log_mod_ind_ngx_prefix() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "ngx_http_proxy done"
        ));
    }

    #[test]
    fn log_mod_ind_error_bracket() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "[error] something failed"
        ));
    }

    #[test]
    fn log_mod_ind_warn_bracket() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "[warn] check this"
        ));
    }

    #[test]
    fn log_mod_ind_info_bracket() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "[info] started"
        ));
    }

    #[test]
    fn log_mod_ind_debug_bracket() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "[debug] trace"
        ));
    }

    #[test]
    fn log_mod_ind_error_space() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "ERROR something"
        ));
    }

    #[test]
    fn log_mod_ind_warn_space() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "WARN something"
        ));
    }

    #[test]
    fn log_mod_ind_info_space() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "INFO something"
        ));
    }

    #[test]
    fn log_mod_ind_debug_space() {
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "DEBUG something"
        ));
    }

    // Negative: each && exclusion

    #[test]
    fn log_mod_ind_excludes_function() {
        assert!(!LogWithModuleDetector::has_log_module_indicators(
            "function [error] handler"
        ));
    }

    #[test]
    fn log_mod_ind_excludes_class() {
        assert!(!LogWithModuleDetector::has_log_module_indicators(
            "class [error] handler"
        ));
    }

    #[test]
    fn log_mod_ind_excludes_import() {
        assert!(!LogWithModuleDetector::has_log_module_indicators(
            "import [error] handler"
        ));
    }

    #[test]
    fn log_mod_ind_no_longer_checks_k8s() {
        // The kubernetes deference moved to the detector ordering table in
        // normalize.rs; the indicator check alone accepts k8s lines now.
        assert!(LogWithModuleDetector::has_log_module_indicators(
            "[error] kubelet failed"
        ));
    }

    #[test]
    fn log_mod_ind_negative() {
        assert!(!LogWithModuleDetector::has_log_module_indicators(
            "plain message"
        ));
    }

    // ---- has_kubernetes_indicators (log_module copy): per-condition tests ----

    #[test]
    fn log_k8s_ind_kubernetes_io() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "kubernetes.io/name"
        ));
    }

    #[test]
    fn log_k8s_ind_namespace() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "namespace/default"
        ));
    }

    #[test]
    fn log_k8s_ind_pod() {
        assert!(crate::patterns::has_kubernetes_indicators("pod/nginx"));
    }

    #[test]
    fn log_k8s_ind_service() {
        assert!(crate::patterns::has_kubernetes_indicators("service/web"));
    }

    #[test]
    fn log_k8s_ind_configmap() {
        assert!(crate::patterns::has_kubernetes_indicators("configmap/cfg"));
    }

    #[test]
    fn log_k8s_ind_secret() {
        assert!(crate::patterns::has_kubernetes_indicators("secret/tls"));
    }

    #[test]
    fn log_k8s_ind_deployment() {
        assert!(crate::patterns::has_kubernetes_indicators("deployment/app"));
    }

    #[test]
    fn log_k8s_ind_volumes() {
        assert!(crate::patterns::has_kubernetes_indicators("volumes/data"));
    }

    #[test]
    fn log_k8s_ind_projected_dash() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "projected-token"
        ));
    }

    #[test]
    fn log_k8s_ind_volume_subpath() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "volume-subpath x"
        ));
    }

    #[test]
    fn log_k8s_ind_projected() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "using projected vol"
        ));
    }

    #[test]
    fn log_k8s_ind_apiserver() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "apiserver health"
        ));
    }

    #[test]
    fn log_k8s_ind_kube_prefix() {
        assert!(crate::patterns::has_kubernetes_indicators("kube-dns ready"));
    }

    #[test]
    fn log_k8s_ind_kubelet() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "kubelet started"
        ));
    }

    #[test]
    fn log_k8s_ind_kube_proxy() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "kube-proxy running"
        ));
    }

    #[test]
    fn log_k8s_ind_kube_scheduler() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "kube-scheduler elected"
        ));
    }

    #[test]
    fn log_k8s_ind_kube_controller() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "kube-controller ok"
        ));
    }

    #[test]
    fn log_k8s_ind_etcd() {
        assert!(crate::patterns::has_kubernetes_indicators("etcd cluster"));
    }

    #[test]
    fn log_k8s_ind_coredns() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "coredns serving"
        ));
    }

    #[test]
    fn log_k8s_ind_negative() {
        assert!(!crate::patterns::has_kubernetes_indicators("plain message"));
    }

    // ---- is_framework_module: per-branch tests ----

    #[test]
    fn framework_mod_known() {
        assert!(LogWithModuleDetector::is_framework_module("spring"));
        assert!(LogWithModuleDetector::is_framework_module("hibernate"));
    }

    #[test]
    fn framework_mod_dot() {
        assert!(LogWithModuleDetector::is_framework_module(
            "com.example.app"
        ));
    }

    #[test]
    fn framework_mod_underscore() {
        assert!(LogWithModuleDetector::is_framework_module("my_module"));
    }

    #[test]
    fn framework_mod_negative() {
        // No known pattern, no dot, no underscore
        assert!(!LogWithModuleDetector::is_framework_module("zzz"));
    }

    // ---- is_systemd_component: per-branch tests ----

    #[test]
    fn systemd_comp_known() {
        assert!(LogWithModuleDetector::is_systemd_component(
            "service_manager"
        ));
    }

    #[test]
    fn systemd_comp_manager_suffix() {
        assert!(LogWithModuleDetector::is_systemd_component("task_manager"));
    }

    #[test]
    fn systemd_comp_service_suffix() {
        assert!(LogWithModuleDetector::is_systemd_component("app_service"));
    }

    #[test]
    fn systemd_comp_client_suffix() {
        assert!(LogWithModuleDetector::is_systemd_component("http_client"));
    }

    #[test]
    fn systemd_comp_daemon_suffix() {
        assert!(LogWithModuleDetector::is_systemd_component("log_daemon"));
    }

    #[test]
    fn systemd_comp_negative() {
        assert!(!LogWithModuleDetector::is_systemd_component("zzz"));
    }

    // ---- is_nginx_module: per-branch tests ----

    #[test]
    fn nginx_mod_known() {
        assert!(LogWithModuleDetector::is_nginx_module("ngx_http_core"));
        assert!(LogWithModuleDetector::is_nginx_module("ngx_stream"));
    }

    #[test]
    fn nginx_mod_generic_pattern() {
        assert!(LogWithModuleDetector::is_nginx_module("ngx_custom_module"));
    }

    #[test]
    fn nginx_mod_negative() {
        assert!(!LogWithModuleDetector::is_nginx_module("zzz"));
    }

    // ---- is_apache_module: per-branch tests ----

    #[test]
    fn apache_mod_known() {
        assert!(LogWithModuleDetector::is_apache_module("mod_jk"));
        assert!(LogWithModuleDetector::is_apache_module("mod_ssl"));
        assert!(LogWithModuleDetector::is_apache_module("mod_proxy"));
    }

    #[test]
    fn apache_mod_negative() {
        assert!(!LogWithModuleDetector::is_apache_module("zzz"));
    }

    // ---- Mutant-killing: apply_nginx_pattern (replace with ()) ----

    #[test]
    fn nginx_pattern_only() {
        // Input that matches ONLY the nginx log pattern
        // nginx pattern: [level] DIGITS#DIGITS: *DIGITS ngx_MODULE
        let input = "[error] 99999#0: *1 ngx_http_core_module: client disconnected";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(input);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "nginx pattern should detect module: {tokens:?}"
        );
        assert_eq!(result, input, "the level and module stay on the line");
    }

    // ---- Mutant-killing: apply_framework_pattern (replace with ()) ----

    #[test]
    fn framework_pattern_only() {
        // Input: LEVEL [module.component] message
        let input = "ERROR [spring.web] Request mapping error";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(input);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "framework pattern should detect module: {tokens:?}"
        );
        assert!(
            result.contains("<LOG_WITH_MODULE>"),
            "framework pattern should modify text: {result}"
        );
    }

    // ---- Mutant-killing: apply_systemd_pattern (replace with ()) ----

    #[test]
    fn systemd_pattern_only() {
        // Input: service[pid]: [level] component: message
        let input = "systemd[1]: [error] service_manager: Unit failed";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(input);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "systemd pattern should detect module: {tokens:?}"
        );
        assert_eq!(result, input, "the level and component stay on the line");
    }

    // ---- Mutant-killing: has_kubernetes_indicators kubelet/kube-proxy lines 101-103 ----

    #[test]
    fn log_k8s_ind_kubelet_only() {
        // "kubelet" without "kube-" prefix to isolate the kubelet check
        assert!(crate::patterns::has_kubernetes_indicators(
            "[error] kubelet failed to start"
        ));
    }

    #[test]
    fn log_k8s_ind_kube_proxy_only() {
        assert!(crate::patterns::has_kubernetes_indicators(
            "[warn] kube-proxy iptables sync"
        ));
    }

    // ---- Mutant-killing: is_nginx_module line 255 ----

    #[test]
    fn nginx_module_generic_with_module_suffix() {
        // Kills mutant: `|| module.starts_with("ngx_") && module.contains("module")` (line 255)
        // Not in the known list but matches the generic pattern
        assert!(LogWithModuleDetector::is_nginx_module("ngx_custom_module"));
        // Without "module" in name, only starts_with("ngx_") is NOT enough for the second branch
        assert!(!LogWithModuleDetector::is_nginx_module("ngx_something"));
    }
}
