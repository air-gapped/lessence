use super::Token;
use regex::Regex;
use std::sync::LazyLock;

const LOG_LEVELS: [&str; 9] = [
    "error",
    "warn",
    "warning",
    "info",
    "information",
    "debug",
    "trace",
    "fatal",
    "critical",
];
const LEVEL_KEYS: &str = "level|severity|lvl";
const COMPONENT_KEYS: &str = "component|service|module|logger|source";

fn level_values() -> String {
    LOG_LEVELS.join("|")
}

static JSON_LEVEL_FIRST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"\{{"(?:{LEVEL_KEYS})"\s*:\s*"({})"[^}}]*"(?:{COMPONENT_KEYS})"\s*:\s*"([^"]+)"[^}}]*\}}"#,
        level_values()
    ))
    .unwrap()
});

static JSON_COMPONENT_FIRST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"\{{"(?:{COMPONENT_KEYS})"\s*:\s*"([^"]+)"[^}}]*"(?:{LEVEL_KEYS})"\s*:\s*"({})"[^}}]*\}}"#,
        level_values()
    ))
    .unwrap()
});

static LOGFMT_STRUCTURED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?:^|\s)(?:{LEVEL_KEYS})=({})\s+(?:{COMPONENT_KEYS})=([^\s]+)",
        level_values()
    ))
    .unwrap()
});

static DOCKER_JSON_FILE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{[^}]*"log":\s*"[^"]*\[(INFO|ERROR|WARN|DEBUG)\]\s+([^:]+):[^"]*"[^}]*\}"#)
        .unwrap()
});

const MIN_COMPONENT_LEN: usize = 3;
const MAX_COMPONENT_LEN: usize = 50;

#[derive(Clone, Copy)]
enum FieldOrder {
    LevelFirst,
    ComponentFirst,
}

impl FieldOrder {
    fn level_and_component_groups(self) -> (usize, usize) {
        match self {
            Self::LevelFirst => (1, 2),
            Self::ComponentFirst => (2, 1),
        }
    }
}

pub struct StructuredMessageDetector;

impl StructuredMessageDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let (text, mut tokens) = Self::detect_json_records(text);
        tokens.extend(Self::detect_logfmt_records(&text).1);
        (text, tokens)
    }

    pub(crate) fn detect_json_records(text: &str) -> (String, Vec<Token>) {
        let mut tokens = Vec::new();
        if Self::has_structured_indicators(text) {
            Self::apply_container_pattern(text, &mut tokens);
            Self::apply_json_pattern(text, &mut tokens);
            Self::apply_json_alt_pattern(text, &mut tokens);
        }
        (text.to_string(), tokens)
    }

    pub(crate) fn detect_logfmt_records(text: &str) -> (String, Vec<Token>) {
        let mut tokens = Vec::new();
        if Self::has_structured_indicators(text) {
            Self::apply_logfmt_pattern(text, &mut tokens);
        }
        (text.to_string(), tokens)
    }

    fn has_level_or_component_key(text: &str) -> bool {
        text.contains(r#""level":"#)
            || text.contains(r#""severity":"#)
            || text.contains(r#""component":"#)
            || text.contains(r#""service":"#)
            || text.contains("level=")
            || text.contains("component=")
    }

    fn has_json_or_logfmt_structure(text: &str) -> bool {
        text.contains('{') || text.contains('=')
    }

    fn is_payload_json(text: &str) -> bool {
        text.contains(r#""data":"#)
            || text.contains(r#""result":"#)
            || text.contains(r#""response":"#)
    }

    pub(crate) fn has_structured_indicators(text: &str) -> bool {
        Self::has_level_or_component_key(text)
            && Self::has_json_or_logfmt_structure(text)
            && !Self::is_payload_json(text)
    }

    fn collect(
        text: &str,
        tokens: &mut Vec<Token>,
        regex: &Regex,
        order: FieldOrder,
        accept: impl Fn(&str, &str) -> bool,
    ) {
        let (level_group, component_group) = order.level_and_component_groups();
        for caps in regex.captures_iter(text) {
            if Self::inside_quotes(text, caps.get(0).unwrap().start()) {
                continue;
            }
            let level = caps.get(level_group).unwrap().as_str();
            let component = caps.get(component_group).unwrap().as_str();

            if accept(component, level) {
                tokens.push(Token::StructuredMessage {
                    component: component.to_lowercase(),
                    level: level.to_lowercase(),
                });
            }
        }
    }

    fn inside_quotes(text: &str, at: usize) -> bool {
        (0..at)
            .filter(|&i| super::toggles_quote(text.as_bytes(), i))
            .count()
            % 2
            == 1
    }

    fn apply_container_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::collect(
            text,
            tokens,
            &DOCKER_JSON_FILE_REGEX,
            FieldOrder::LevelFirst,
            |component, _bracketed_level| Self::is_application_component(component),
        );
    }

    fn apply_json_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::collect(
            text,
            tokens,
            &JSON_LEVEL_FIRST_REGEX,
            FieldOrder::LevelFirst,
            Self::is_valid_structured_log,
        );
    }

    fn apply_json_alt_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::collect(
            text,
            tokens,
            &JSON_COMPONENT_FIRST_REGEX,
            FieldOrder::ComponentFirst,
            Self::is_valid_structured_log,
        );
    }

    fn apply_logfmt_pattern(text: &str, tokens: &mut Vec<Token>) {
        Self::collect(
            text,
            tokens,
            &LOGFMT_STRUCTURED_REGEX,
            FieldOrder::LevelFirst,
            Self::is_valid_structured_log,
        );
    }

    fn is_application_component(component: &str) -> bool {
        let app_components = [
            "application",
            "database",
            "cache",
            "auth",
            "payment",
            "notification",
            "user",
            "order",
            "inventory",
            "billing",
            "analytics",
            "monitoring",
            "logging",
            "metrics",
        ];

        app_components
            .iter()
            .any(|&app_comp| component.contains(app_comp))
            || component.ends_with("-service")
            || component.ends_with("_service")
            || component.ends_with("-api")
            || component.ends_with("_api")
            || component.ends_with("-client")
            || component.ends_with("_client")
    }

    fn is_microservice_component(component: &str) -> bool {
        component.contains("service")
            || component.contains("api")
            || component.contains("gateway")
            || component.contains("proxy")
            || component.contains("balancer")
            || component.contains("registry")
            || component.contains("discovery")
            || component.contains("config")
            || component.contains("auth")
            || component.contains("user")
            || component.contains("payment")
            || component.contains("order")
            || component.contains("inventory")
            || component.contains("notification")
    }

    fn is_framework_component(component: &str) -> bool {
        let framework_components = [
            "spring",
            "hibernate",
            "jackson",
            "slf4j",
            "logback",
            "jersey",
            "servlet",
            "tomcat",
            "jetty",
            "netty",
            "akka",
            "vertx",
            "reactor",
            "rxjava",
            "guava",
        ];

        framework_components
            .iter()
            .any(|&framework| component.contains(framework))
            || Self::is_package_name(component)
    }

    fn is_package_name(component: &str) -> bool {
        component.contains('.') && !component.contains(' ')
    }

    fn is_infrastructure_component(component: &str) -> bool {
        let infra_components = [
            "nginx",
            "apache",
            "haproxy",
            "envoy",
            "traefik",
            "consul",
            "vault",
            "nomad",
            "prometheus",
            "grafana",
            "elasticsearch",
            "logstash",
            "kibana",
            "fluentd",
            "redis",
            "memcached",
            "mongodb",
            "postgresql",
            "mysql",
        ];

        infra_components
            .iter()
            .any(|&infra| component.contains(infra))
    }

    fn is_component_shaped(component: &str) -> bool {
        (MIN_COMPONENT_LEN..=MAX_COMPONENT_LEN).contains(&component.len())
            && component
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            && !component.chars().all(|c| c.is_ascii_digit())
    }

    fn is_valid_structured_log(component: &str, level: &str) -> bool {
        if !LOG_LEVELS.contains(&level.to_lowercase().as_str()) {
            return false;
        }

        Self::is_application_component(component)
            || Self::is_microservice_component(component)
            || Self::is_framework_component(component)
            || Self::is_infrastructure_component(component)
            || Self::is_component_shaped(component)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kubernetes_component_is_a_component_like_any_other() {
        let k8s_line = r#"{"level":"info","ts":"2024-01-01T10:00:00.000Z","component":"kubelet","msg":"Starting container"}"#;
        let (_result, tokens) = StructuredMessageDetector::detect_and_replace(k8s_line);

        assert!(
            !tokens.is_empty(),
            "no word on the line switches the detector off"
        );
    }

    #[test]
    fn test_microservice_structured_detection() {
        let microservice_line = r#"{"level":"error","timestamp":"2024-01-01T10:00:00Z","service":"payment-api","message":"Payment failed"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(microservice_line);
        assert_eq!(result, microservice_line);
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "payment-api".to_string(),
                level: "error".to_string()
            }]
        );
    }

    #[test]
    fn test_logfmt_structured_detection() {
        let logfmt_line =
            "time=2024-01-01T10:00:00Z level=info component=api-gateway msg=\"Request received\"";
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(logfmt_line);

        assert_eq!(result, logfmt_line, "text must be preserved verbatim");
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "api-gateway".to_string(),
                level: "info".to_string()
            }]
        );
    }

    #[test]
    fn test_container_structured_detection() {
        let container_line = r#"{"log":"2024-01-01T10:00:00.000Z [INFO] application: Starting server\n","stream":"stdout","level":"info"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(container_line);

        assert_eq!(result, container_line, "text must be preserved verbatim");
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "application".to_string(),
                level: "info".to_string()
            }]
        );
    }

    #[test]
    fn test_microservice_component() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "payment-api"
        ));
        assert!(StructuredMessageDetector::is_microservice_component(
            "user-service"
        ));
        assert!(!StructuredMessageDetector::is_microservice_component(
            "random-thing"
        ));
    }

    #[test]
    fn test_infrastructure_component() {
        assert!(StructuredMessageDetector::is_infrastructure_component(
            "nginx"
        ));
        assert!(StructuredMessageDetector::is_infrastructure_component(
            "redis-cache"
        ));
        assert!(!StructuredMessageDetector::is_infrastructure_component(
            "my-app"
        ));
    }

    #[test]
    fn test_framework_component() {
        assert!(StructuredMessageDetector::is_framework_component(
            "spring.web"
        ));
        assert!(StructuredMessageDetector::is_framework_component(
            "com.example.App"
        ));
        assert!(!StructuredMessageDetector::is_framework_component("my-app"));
    }

    #[test]
    fn test_valid_structured_log() {
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "api-gateway",
            "info"
        ));
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "payment-service",
            "error"
        ));
    }

    #[test]
    fn test_invalid_structured_log_bad_level() {
        assert!(!StructuredMessageDetector::is_valid_structured_log(
            "api-gateway",
            "invalid"
        ));
    }

    #[test]
    fn test_invalid_structured_log_all_digits() {
        assert!(!StructuredMessageDetector::is_valid_structured_log(
            "123", "info"
        ));
    }

    #[test]
    fn test_structured_indicators_json() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"info","component":"app"}"#
        ));
    }

    #[test]
    fn test_structured_indicators_logfmt() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            "level=info component=app"
        ));
    }

    #[test]
    fn test_no_false_positives() {
        let non_log_cases = vec![
            r#"{"user_id": 12345, "action": "login", "result": "success"}"#,
            r#"{"api_response": {"data": [], "status": 200}}"#,
            r#"{"config": {"level": "production", "component": "database"}}"#,
        ];

        for test_case in non_log_cases {
            let (_result, tokens) = StructuredMessageDetector::detect_and_replace(test_case);

            assert!(
                !tokens
                    .iter()
                    .any(|token| matches!(token, Token::StructuredMessage { .. })),
                "data JSON is not a log record: {test_case} -> {tokens:?}"
            );
        }
    }

    #[test]
    fn test_multiple_structured_messages() {
        let multi_line = r#"Received: {"level":"info","component":"api","msg":"Request"} Processing: {"level":"debug","component":"handler","msg":"Validation"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(multi_line);

        let structured_count = tokens
            .iter()
            .filter(|token| matches!(token, Token::StructuredMessage { .. }))
            .count();

        assert_eq!(result, multi_line, "text must be preserved verbatim");
        assert_eq!(structured_count, 2);
    }

    #[test]
    fn a_key_ending_in_level_is_not_the_level_key() {
        let line = r#"{"risk_level":"critical","component":"payment-api","level":"info"}"#;
        let (_r, tokens) = StructuredMessageDetector::detect_and_replace(line);
        assert!(
            !tokens.contains(&Token::StructuredMessage {
                component: "payment-api".to_string(),
                level: "critical".to_string()
            }),
            "{tokens:?}"
        );
    }

    #[test]
    fn a_component_first_record_reads_its_level() {
        let line = r#"{"component":"payment-api","level":"warn","msg":"x"}"#;
        let (_r, tokens) = StructuredMessageDetector::detect_and_replace(line);
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "payment-api".to_string(),
                level: "warn".to_string()
            }]
        );
    }

    #[test]
    fn a_logfmt_pair_inside_a_quoted_value_is_not_the_record_level() {
        let line = r#"level=error msg="replayed level=info component=api-gw""#;
        let (_r, tokens) = StructuredMessageDetector::detect_and_replace(line);
        assert!(tokens.is_empty(), "{tokens:?}");
        let (_r, tokens) =
            StructuredMessageDetector::detect_and_replace("xlevel=info component=api-gw");
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn struct_ind_level_json() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"error"}"#
        ));
    }

    #[test]
    fn struct_ind_severity_json() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"severity":"warn"}"#
        ));
    }

    #[test]
    fn struct_ind_component_json() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"component":"api"}"#
        ));
    }

    #[test]
    fn struct_ind_service_json() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"service":"web"}"#
        ));
    }

    #[test]
    fn struct_ind_level_logfmt() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            "level=error component=api"
        ));
    }

    #[test]
    fn struct_ind_component_logfmt() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            "component=api msg=hello"
        ));
    }

    #[test]
    fn a_json_level_key_without_braces_or_equals_has_no_structure() {
        for (text, case) in [
            (r#""level":"error" plain"#, "struct_ind_requires_structure"),
            (
                r#""level":"error" no structure"#,
                "struct_ind_needs_both_keyword_and_structure",
            ),
        ] {
            assert!(
                !StructuredMessageDetector::has_structured_indicators(text),
                "{case}: a level key with no `{{` and no `=` fails the structure check"
            );
        }
    }

    #[test]
    fn struct_ind_excludes_data_json() {
        assert!(!StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"info","data":"response"}"#
        ));
    }

    #[test]
    fn struct_ind_excludes_result_json() {
        assert!(!StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"info","result":"ok"}"#
        ));
    }

    #[test]
    fn struct_ind_excludes_response_json() {
        assert!(!StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"info","response":"200"}"#
        ));
    }

    #[test]
    fn no_word_on_the_line_switches_the_detector_off() {
        assert!(StructuredMessageDetector::has_structured_indicators(
            r#"{"level":"info","component":"kubelet"}"#
        ));
    }

    #[test]
    fn struct_ind_negative() {
        assert!(!StructuredMessageDetector::has_structured_indicators(
            "plain log message"
        ));
    }

    #[test]
    fn app_comp_known() {
        assert!(
            StructuredMessageDetector::is_application_component("my-application"),
            "a listed word anywhere in the component matches: substring, not equality"
        );
        assert!(StructuredMessageDetector::is_application_component(
            "database-primary"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "redis-cache"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "auth-handler"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "payment-proc"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "notification-svc"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "user-mgmt"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "order-processor"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "inventory-svc"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "billing-engine"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "analytics-pipeline"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "monitoring-agent"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "logging-collector"
        ));
    }

    #[test]
    fn app_comp_service_suffix() {
        assert!(StructuredMessageDetector::is_application_component(
            "auth-service"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "auth_service"
        ));
    }

    #[test]
    fn app_comp_api_suffix() {
        assert!(StructuredMessageDetector::is_application_component(
            "user-api"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "user_api"
        ));
    }

    #[test]
    fn app_comp_client_suffix() {
        assert!(StructuredMessageDetector::is_application_component(
            "http-client"
        ));
        assert!(StructuredMessageDetector::is_application_component(
            "http_client"
        ));
    }

    #[test]
    fn app_comp_negative() {
        assert!(!StructuredMessageDetector::is_application_component("zzz"));
    }

    #[test]
    fn micro_comp_service() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "user-service"
        ));
    }

    #[test]
    fn micro_comp_gateway() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "api-gateway"
        ));
    }

    #[test]
    fn micro_comp_proxy() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "envoy-proxy"
        ));
    }

    #[test]
    fn micro_comp_balancer() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "load-balancer"
        ));
    }

    #[test]
    fn micro_comp_registry() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "service-registry"
        ));
    }

    #[test]
    fn micro_comp_discovery() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "service-discovery"
        ));
    }

    #[test]
    fn micro_comp_config() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "config-server"
        ));
    }

    #[test]
    fn micro_comp_auth() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "auth-handler"
        ));
    }

    #[test]
    fn micro_comp_user() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "user-mgmt"
        ));
    }

    #[test]
    fn micro_comp_payment() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "payment-proc"
        ));
    }

    #[test]
    fn micro_comp_order() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "order-mgmt"
        ));
    }

    #[test]
    fn micro_comp_inventory() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "inventory-svc"
        ));
    }

    #[test]
    fn micro_comp_notification() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "notification-svc"
        ));
    }

    #[test]
    fn micro_comp_negative() {
        assert!(!StructuredMessageDetector::is_microservice_component("zzz"));
    }

    #[test]
    fn valid_struct_log_invalid_level() {
        assert!(!StructuredMessageDetector::is_valid_structured_log(
            "web", "xyz"
        ));
    }

    #[test]
    fn valid_struct_log_app_component() {
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "web", "error"
        ));
    }

    #[test]
    fn valid_struct_log_micro_component() {
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "api-gateway",
            "info"
        ));
    }

    #[test]
    fn valid_struct_log_framework_component() {
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "spring", "debug"
        ));
    }

    #[test]
    fn valid_struct_log_infra_component() {
        assert!(StructuredMessageDetector::is_valid_structured_log(
            "nginx", "warn"
        ));
    }

    #[test]
    fn valid_struct_log_generic_valid() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("my-app", "error"),
            "MIN_COMPONENT_LEN..=MAX_COMPONENT_LEN chars of [A-Za-z0-9_.-], not all digits"
        );
    }

    #[test]
    fn a_component_outside_the_generic_shape_is_refused() {
        let long = "a".repeat(MAX_COMPONENT_LEN + 1);
        for (component, level, case) in [
            ("ab", "error", "valid_struct_log_too_short"),
            (long.as_str(), "error", "valid_struct_log_too_long"),
            ("12345", "error", "valid_struct_log_all_digits"),
            ("my app!", "error", "valid_struct_log_special_chars"),
            ("ab", "info", "valid_structured_log_too_short"),
            (long.as_str(), "info", "valid_structured_log_too_long"),
            ("12345", "info", "valid_structured_log_all_digits_fails"),
            (
                "has space",
                "info",
                "valid_structured_log_invalid_chars_fails",
            ),
        ] {
            assert!(
                !StructuredMessageDetector::is_valid_structured_log(component, level),
                "{case}: {component}"
            );
        }
    }

    #[test]
    fn the_generic_shape_admits_both_length_bounds() {
        for component in ["abc".to_string(), "a".repeat(MAX_COMPONENT_LEN)] {
            assert!(
                StructuredMessageDetector::is_component_shaped(&component),
                "{} chars is inside MIN_COMPONENT_LEN..=MAX_COMPONENT_LEN",
                component.len()
            );
        }
    }

    #[test]
    fn each_classifier_alone_admits_a_component_the_generic_shape_refuses() {
        type Classifier = fn(&str) -> bool;
        let classifiers: [(&str, Classifier); 4] = [
            (
                "application",
                StructuredMessageDetector::is_application_component,
            ),
            (
                "microservice",
                StructuredMessageDetector::is_microservice_component,
            ),
            (
                "framework",
                StructuredMessageDetector::is_framework_component,
            ),
            (
                "infrastructure",
                StructuredMessageDetector::is_infrastructure_component,
            ),
        ];
        for (component, holds) in [
            ("my database", "application"),
            ("edge gateway", "microservice"),
            ("spring boot", "framework"),
            ("nginx ingress", "infrastructure"),
        ] {
            assert!(
                !StructuredMessageDetector::is_component_shaped(component),
                "{component}: a space fails the generic shape"
            );
            for (name, classify) in classifiers {
                assert_eq!(
                    classify(component),
                    name == holds,
                    "{component}: only the {holds} classifier holds, not {name}"
                );
            }
            assert!(
                StructuredMessageDetector::is_valid_structured_log(component, "info"),
                "{component}: the {holds} classifier alone admits it"
            );
        }
        assert!(
            !StructuredMessageDetector::is_valid_structured_log("my database", "bogus"),
            "an unknown level is refused whatever the component"
        );
    }

    #[test]
    fn a_docker_json_file_record_with_a_level_key_reaches_the_container_pattern() {
        let (_, tokens) = StructuredMessageDetector::detect_and_replace(
            r#"{"level":"x","log":"[INFO] database: connected\n","stream":"stdout"}"#,
        );
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "database".to_string(),
                level: "info".to_string(),
            }],
            "the prefilter admits a container record that carries a level key"
        );
        let (_, tokens) = StructuredMessageDetector::detect_and_replace(
            r#"{"level":"x","log":"[INFO] worker: connected\n","stream":"stdout"}"#,
        );
        assert!(
            tokens.is_empty(),
            "the container pattern takes only an application component: {tokens:?}"
        );
    }

    #[test]
    fn the_component_first_pattern_reads_the_level_from_group_two() {
        let (_, tokens) = StructuredMessageDetector::detect_and_replace(
            r#"{"service":"db-proxy","level":"warn"}"#,
        );
        assert_eq!(
            tokens,
            vec![Token::StructuredMessage {
                component: "db-proxy".to_string(),
                level: "warn".to_string(),
            }]
        );
    }

    #[test]
    fn valid_struct_log_each_level() {
        for level in [
            "error",
            "warn",
            "warning",
            "info",
            "information",
            "debug",
            "trace",
            "fatal",
            "critical",
        ] {
            assert!(
                StructuredMessageDetector::is_valid_structured_log("web", level),
                "level '{level}' should be valid"
            );
        }
    }

    #[test]
    fn apply_json_pattern_emits_token_preserves_text() {
        let input = r#"{"level":"error","component":"payment-api","msg":"fail"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(input);
        assert_eq!(result, input, "text must be preserved verbatim");
        assert!(
            !tokens.is_empty(),
            "JSON pattern should produce tokens: an apply_json_pattern that does nothing emits none"
        );
    }

    #[test]
    fn apply_json_primary_regex_matches_directly() {
        let input = r#"{"level":"error","service":"order-api"}"#;
        let m = JSON_LEVEL_FIRST_REGEX.captures(input);
        assert!(
            m.is_some(),
            "Primary JSON regex should match level-first JSON, input: {input}"
        );
    }

    #[test]
    fn apply_logfmt_pattern_emits_token_preserves_text() {
        let input = "level=info component=api-gateway msg=\"Request received\"";
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(input);
        assert_eq!(result, input, "text must be preserved verbatim");
        assert!(
            !tokens.is_empty(),
            "logfmt pattern should produce tokens: an apply_logfmt_pattern that does nothing emits none"
        );
    }

    #[test]
    fn apply_json_pattern_produces_correct_token() {
        let input = r#"{"level":"warn","service":"billing-api","msg":"retry"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(input);
        assert_eq!(result, input, "text must be preserved verbatim");
        assert!(!tokens.is_empty());
        if let Token::StructuredMessage { component, level } = &tokens[0] {
            assert_eq!(component, "billing-api");
            assert_eq!(level, "warn");
        } else {
            panic!("Expected StructuredMessage token");
        }
    }

    #[test]
    fn apply_logfmt_pattern_produces_correct_token() {
        let input = "level=error component=my-registry msg=\"connection lost\"";
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(input);
        assert_eq!(result, input, "text must be preserved verbatim");
        assert!(!tokens.is_empty());
        if let Token::StructuredMessage { component, level } = &tokens[0] {
            assert_eq!(component, "my-registry");
            assert_eq!(level, "error");
        } else {
            panic!("Expected StructuredMessage token");
        }
    }

    #[test]
    fn app_comp_only_service_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz-service"),
            "xyz is in no list: only the -service suffix matches"
        );
    }

    #[test]
    fn app_comp_only_underscore_service_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz_service"),
            "xyz is in no list: only the _service suffix matches"
        );
    }

    #[test]
    fn app_comp_only_api_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz-api"),
            "xyz is in no list: only the -api suffix matches"
        );
    }

    #[test]
    fn app_comp_only_underscore_api_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz_api"),
            "xyz is in no list: only the _api suffix matches"
        );
    }

    #[test]
    fn app_comp_only_client_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz-client"),
            "xyz is in no list: only the -client suffix matches"
        );
    }

    #[test]
    fn app_comp_only_underscore_client_suffix() {
        assert!(
            StructuredMessageDetector::is_application_component("xyz_client"),
            "xyz is in no list: only the _client suffix matches"
        );
    }

    #[test]
    fn app_comp_no_match_at_all() {
        assert!(!StructuredMessageDetector::is_application_component(
            "xyz-handler"
        ));
    }

    #[test]
    fn micro_comp_only_gateway() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-gateway-1"
        ));
        let s = "my-gateway-1";
        assert!(!s.contains("service") && !s.contains("api") && !s.contains("proxy"));
    }

    #[test]
    fn micro_comp_only_balancer() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-balancer"
        ));
        assert!(!"my-balancer".contains("service"));
    }

    #[test]
    fn micro_comp_only_registry() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-registry"
        ));
    }

    #[test]
    fn micro_comp_only_discovery() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-discovery"
        ));
    }

    #[test]
    fn micro_comp_only_config() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-config"
        ));
    }

    #[test]
    fn micro_comp_only_notification() {
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-notification"
        ));
    }

    #[test]
    fn valid_struct_log_only_app_component() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("metrics-handler", "info"),
            "exactly one is_*_component classifier holds for metrics-handler"
        );
        assert!(StructuredMessageDetector::is_application_component(
            "metrics-handler"
        ));
        assert!(!StructuredMessageDetector::is_microservice_component(
            "metrics-handler"
        ));
        assert!(!StructuredMessageDetector::is_framework_component(
            "metrics-handler"
        ));
        assert!(!StructuredMessageDetector::is_infrastructure_component(
            "metrics-handler"
        ));
    }

    #[test]
    fn valid_struct_log_only_micro_component() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("my-gateway-1", "info"),
            "exactly one is_*_component classifier holds for my-gateway-1"
        );
        assert!(!StructuredMessageDetector::is_application_component(
            "my-gateway-1"
        ));
        assert!(StructuredMessageDetector::is_microservice_component(
            "my-gateway-1"
        ));
        assert!(!StructuredMessageDetector::is_framework_component(
            "my-gateway-1"
        ));
        assert!(!StructuredMessageDetector::is_infrastructure_component(
            "my-gateway-1"
        ));
    }

    #[test]
    fn valid_struct_log_only_framework_component() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("spring-boot", "info"),
            "exactly one is_*_component classifier holds for spring-boot"
        );
        assert!(!StructuredMessageDetector::is_application_component(
            "spring-boot"
        ));
        assert!(!StructuredMessageDetector::is_microservice_component(
            "spring-boot"
        ));
        assert!(StructuredMessageDetector::is_framework_component(
            "spring-boot"
        ));
        assert!(!StructuredMessageDetector::is_infrastructure_component(
            "spring-boot"
        ));
    }

    #[test]
    fn valid_struct_log_only_infra_component() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("my-nginx-1", "info"),
            "exactly one is_*_component classifier holds for my-nginx-1"
        );
        assert!(!StructuredMessageDetector::is_application_component(
            "my-nginx-1"
        ));
        assert!(!StructuredMessageDetector::is_microservice_component(
            "my-nginx-1"
        ));
        assert!(!StructuredMessageDetector::is_framework_component(
            "my-nginx-1"
        ));
        assert!(StructuredMessageDetector::is_infrastructure_component(
            "my-nginx-1"
        ));
    }

    #[test]
    fn microservice_component_each_keyword() {
        let keywords = [
            "service",
            "api",
            "gateway",
            "proxy",
            "balancer",
            "registry",
            "discovery",
            "config",
            "auth",
            "user",
            "payment",
            "order",
            "inventory",
            "notification",
        ];
        for kw in keywords {
            let component = format!("my-{kw}-1");
            assert!(
                StructuredMessageDetector::is_microservice_component(&component),
                "should detect microservice component with keyword '{kw}': {component}"
            );
        }
    }

    #[test]
    fn microservice_component_negative() {
        assert!(!StructuredMessageDetector::is_microservice_component(
            "random-xyz"
        ));
    }

    #[test]
    fn valid_structured_log_generic_component() {
        assert!(
            StructuredMessageDetector::is_valid_structured_log("my-custom-comp", "info"),
            "in no category, admitted by the generic shape alone"
        );
        assert!(!StructuredMessageDetector::is_application_component(
            "my-custom-comp"
        ));
        assert!(!StructuredMessageDetector::is_microservice_component(
            "my-custom-comp"
        ));
        assert!(!StructuredMessageDetector::is_framework_component(
            "my-custom-comp"
        ));
        assert!(!StructuredMessageDetector::is_infrastructure_component(
            "my-custom-comp"
        ));
    }
}
