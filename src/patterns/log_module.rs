use super::Token;
use regex::Regex;
use std::sync::LazyLock;

const BRACKETED_LEVELS: &str =
    "error|warn|warning|info|information|debug|trace|fatal|crit|critical|notice";
const SYSTEMD_BRACKETED_LEVELS: &str = "error|warn|warning|info|information|debug|trace|fatal";
const FRAMEWORK_LEVELS: &str = "ERROR|WARN|WARNING|INFO|INFORMATION|DEBUG|TRACE|FATAL|CRITICAL";

static APACHE_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\[(?P<level>{BRACKETED_LEVELS})\]\s+(?P<module>mod_\w+)"
    ))
    .unwrap()
});

static NGINX_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\[(?P<level>{BRACKETED_LEVELS})\]\s+\d+#\d+:\s*\*?\d*\s+(?P<module>ngx_\w+(?:_module)?)"
    ))
    .unwrap()
});

static FRAMEWORK_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<level>{FRAMEWORK_LEVELS})\s+\[(?P<module>[a-zA-Z][a-zA-Z0-9_.]+)\]"
    ))
    .unwrap()
});

static SYSTEMD_LOG_MODULE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<service>[a-zA-Z][a-zA-Z0-9_-]+)\[\d+\]:\s*\[(?P<level>{SYSTEMD_BRACKETED_LEVELS})\]\s+(?P<component>[a-zA-Z][a-zA-Z0-9_]+):"
    ))
    .unwrap()
});

pub struct LogWithModuleDetector;

impl LogWithModuleDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::has_log_module_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut tokens = Vec::new();

        Self::note_apache_module(text, &mut tokens);
        Self::note_nginx_module(text, &mut tokens);
        let mut result = text.to_string();
        Self::fold_framework_logger(&mut result, &mut tokens);
        Self::note_systemd_component(&result, &mut tokens);

        (result, tokens)
    }

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

    pub(crate) fn has_log_module_indicators(text: &str) -> bool {
        (text.contains("mod_")
            || text.contains("ngx_")
            || text.contains("[error]")
            || text.contains("[warn")
            || text.contains("[info")
            || text.contains("[debug")
            || text.contains("ERROR ")
            || text.contains("WARN ")
            || text.contains("INFO ")
            || text.contains("DEBUG "))
            && !Self::looks_like_source_code(text)
    }

    fn looks_like_source_code(text: &str) -> bool {
        ["function ", "class ", "import "]
            .iter()
            .any(|keyword| text.contains(keyword))
    }

    fn note_apache_module(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &APACHE_LOG_MODULE_REGEX, |caps| {
            let level = &caps["level"];
            let module = &caps["module"];
            Self::is_apache_module(module).then(|| Token::LogWithModule {
                level: level.to_lowercase(),
                module: module.to_string(),
            })
        });
    }

    fn note_nginx_module(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &NGINX_LOG_MODULE_REGEX, |caps| {
            let level = &caps["level"];
            let module = &caps["module"];
            Self::is_nginx_module(module).then(|| Token::LogWithModule {
                level: level.to_lowercase(),
                module: module.to_string(),
            })
        });
    }

    fn fold_framework_logger(text: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(text, tokens, &FRAMEWORK_LOG_MODULE_REGEX, |caps| {
            let level = &caps["level"];
            let module = &caps["module"];
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

    fn note_systemd_component(text: &str, tokens: &mut Vec<Token>) {
        Self::note_matches(text, tokens, &SYSTEMD_LOG_MODULE_REGEX, |caps| {
            let service = &caps["service"];
            let level = &caps["level"];
            let component = &caps["component"];
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

        framework_patterns
            .iter()
            .any(|&pattern| module.contains(pattern))
            || Self::is_package_style(module)
    }

    fn is_package_style(module: &str) -> bool {
        module.contains('.') || module.contains('_')
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

        assert_eq!(
            result, apache_line,
            "the level and module stay on the line; only the token is new"
        );
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
    fn prose_and_source_code_carry_no_log_module() {
        for (case, reason) in [
            ("Regular log message without module", "no indicator"),
            (
                "Processing mod_calculation = result + 5",
                "a mod_ word with no bracketed level before it",
            ),
            (
                "function mod_test() { return true; }",
                "code context is not a log module",
            ),
            (
                "import mod_library from 'package'",
                "code context is not a log module",
            ),
        ] {
            let (result, tokens) = LogWithModuleDetector::detect_and_replace(case);
            assert!(tokens.is_empty(), "{reason}: {case}: {tokens:?}");
            assert_eq!(result, case, "{reason}");
        }
    }

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
    fn no_other_word_switches_the_detector_off() {
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
        assert!(!LogWithModuleDetector::is_framework_module("zzz"));
    }

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

    #[test]
    fn nginx_pattern_only() {
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

    #[test]
    fn framework_pattern_only() {
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

    #[test]
    fn systemd_pattern_only() {
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

    #[test]
    fn nginx_module_generic_with_module_suffix() {
        assert!(
            LogWithModuleDetector::is_nginx_module("ngx_custom_module"),
            "an unknown ngx_ name counts only with module in it"
        );
        assert!(
            !LogWithModuleDetector::is_nginx_module("ngx_something"),
            "the ngx_ prefix alone is not enough"
        );
    }
}
