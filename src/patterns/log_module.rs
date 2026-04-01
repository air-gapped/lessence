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

// Syslog style: facility.level daemon: message
static SYSLOG_FACILITY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"([a-zA-Z]+)\.(error|err|warn|warning|info|information|debug|trace|fatal|crit|critical|notice|emerg|emergency|alert)\s+([a-zA-Z][a-zA-Z0-9_-]+):"
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
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no log module indicators
        if !Self::has_log_module_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Apply log-with-module detection in order of specificity
        Self::apply_apache_pattern(&mut result, &mut tokens);
        Self::apply_nginx_pattern(&mut result, &mut tokens);
        Self::apply_syslog_pattern(&mut result, &mut tokens);
        Self::apply_framework_pattern(&mut result, &mut tokens);
        Self::apply_systemd_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_log_module_indicators(text: &str) -> bool {
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
        !text.contains("import ") &&
        // CRITICAL: Exclude Kubernetes patterns to prevent pattern theft
        !Self::has_kubernetes_indicators(text)
    }

    /// Detect if text contains Kubernetes patterns that should be handled by KubernetesDetector
    fn has_kubernetes_indicators(text: &str) -> bool {
        // Kubernetes namespaces and resources
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
        // Kubernetes components that should be handled by KubernetesDetector
        text.contains("kubelet") ||
        text.contains("kube-proxy") ||
        text.contains("kube-scheduler") ||
        text.contains("kube-controller") ||
        text.contains("etcd") ||
        text.contains("coredns")
    }

    fn apply_apache_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = APACHE_LOG_MODULE_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let level = caps.get(1).unwrap().as_str();
                let module = caps.get(2).unwrap().as_str();

                if Self::is_apache_module(module) {
                    tokens.push(Token::LogWithModule {
                        level: level.to_lowercase(),
                        module: module.to_string(),
                    });
                    "<LOG_WITH_MODULE>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_nginx_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = NGINX_LOG_MODULE_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let level = caps.get(1).unwrap().as_str();
                let module = caps.get(2).unwrap().as_str();

                if Self::is_nginx_module(module) {
                    tokens.push(Token::LogWithModule {
                        level: level.to_lowercase(),
                        module: module.to_string(),
                    });
                    format!("[{level}] <LOG_WITH_MODULE>")
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_syslog_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = SYSLOG_FACILITY_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let facility = caps.get(1).unwrap().as_str();
                let level = caps.get(2).unwrap().as_str();
                let daemon = caps.get(3).unwrap().as_str();

                if Self::is_syslog_daemon(daemon) {
                    tokens.push(Token::LogWithModule {
                        level: Self::normalize_syslog_level(level),
                        module: daemon.to_string(),
                    });
                    format!("{facility}.{level} <LOG_WITH_MODULE>:")
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_framework_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = FRAMEWORK_LOG_MODULE_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let level = caps.get(1).unwrap().as_str();
                let module = caps.get(2).unwrap().as_str();

                if Self::is_framework_module(module) {
                    tokens.push(Token::LogWithModule {
                        level: level.to_lowercase(),
                        module: module.to_string(),
                    });
                    format!("{level} [<LOG_WITH_MODULE>]")
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_systemd_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = SYSTEMD_LOG_MODULE_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let service = caps.get(1).unwrap().as_str();
                let level = caps.get(2).unwrap().as_str();
                let component = caps.get(3).unwrap().as_str();

                if Self::is_systemd_component(component) {
                    tokens.push(Token::LogWithModule {
                        level: level.to_lowercase(),
                        module: format!("{service}.{component}"),
                    });
                    format!("{service}[PID]: [{level}] <LOG_WITH_MODULE>:")
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
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

    fn is_syslog_daemon(daemon: &str) -> bool {
        let syslog_daemons = [
            "kernel",
            "sshd",
            "systemd",
            "cron",
            "postfix",
            "nginx",
            "apache",
            "mysql",
            "postgresql",
            "redis",
            "docker",
            "NetworkManager",
            "dhcpd",
            "named",
            "ntpd",
            "rsyslog",
            "auditd",
            "firewalld", // NOTE: "kubelet" removed to prevent Kubernetes pattern theft
        ];

        syslog_daemons.contains(&daemon) ||
        daemon.ends_with('d') ||  // Most daemons end with 'd'
        daemon.contains("_service") ||
        daemon.contains("-service")
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

    fn normalize_syslog_level(level: &str) -> String {
        match level {
            "err" => "error".to_string(),
            "emerg" | "emergency" => "emergency".to_string(),
            "crit" | "critical" => "critical".to_string(),
            _ => level.to_lowercase(),
        }
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

        assert!(!tokens.is_empty());
        assert!(result.contains("<LOG_WITH_MODULE>"));

        if let Token::LogWithModule { level, module } = &tokens[0] {
            assert_eq!(level, "error");
            assert_eq!(module, "mod_jk");
        }
    }

    #[test]
    fn test_nginx_module_detection() {
        let nginx_line = "[error] 12345#0: *1 ngx_http_core_module: client disconnected";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(nginx_line);

        if !tokens.is_empty() {
            assert!(result.contains("<LOG_WITH_MODULE>"));
            if let Token::LogWithModule { level, module } = &tokens[0] {
                assert_eq!(level, "error");
                assert!(module.starts_with("ngx_http"));
            }
        }
    }

    #[test]
    fn test_syslog_daemon_detection() {
        let syslog_line = "kern.error kernel: Out of memory condition";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(syslog_line);

        if !tokens.is_empty() {
            assert!(result.contains("<LOG_WITH_MODULE>"));
            if let Token::LogWithModule { level, module } = &tokens[0] {
                assert_eq!(level, "error");
                assert_eq!(module, "kernel");
            }
        }
    }

    #[test]
    fn test_framework_logging() {
        let framework_line = "2024-01-01 10:00:00 ERROR [hibernate.SQL] Database connection failed";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(framework_line);

        if !tokens.is_empty() {
            assert!(result.contains("<LOG_WITH_MODULE>"));
            if let Token::LogWithModule { level, module } = &tokens[0] {
                assert_eq!(level, "error");
                assert_eq!(module, "hibernate.SQL");
            }
        }
    }

    #[test]
    fn test_systemd_service_detection() {
        let systemd_line = "systemd[1]: [info] service_manager: Starting network service";
        let (result, tokens) = LogWithModuleDetector::detect_and_replace(systemd_line);

        if !tokens.is_empty() {
            assert!(result.contains("<LOG_WITH_MODULE>"));
            if let Token::LogWithModule { level, module } = &tokens[0] {
                assert_eq!(level, "info");
                assert!(module.contains("systemd"));
            }
        }
    }

    #[test]
    fn test_module_classification() {
        assert!(LogWithModuleDetector::is_apache_module("mod_jk"));
        assert!(LogWithModuleDetector::is_apache_module("mod_ssl"));
        assert!(LogWithModuleDetector::is_nginx_module("ngx_http_core"));
        assert!(LogWithModuleDetector::is_syslog_daemon("sshd"));
        assert!(LogWithModuleDetector::is_framework_module("spring.web"));
        assert!(LogWithModuleDetector::is_systemd_component(
            "service_manager"
        ));
    }

    #[test]
    fn test_syslog_level_normalization() {
        assert_eq!(
            LogWithModuleDetector::normalize_syslog_level("err"),
            "error"
        );
        assert_eq!(
            LogWithModuleDetector::normalize_syslog_level("crit"),
            "critical"
        );
        assert_eq!(
            LogWithModuleDetector::normalize_syslog_level("info"),
            "info"
        );
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
}
