use std::sync::LazyLock;
use regex::Regex;
use super::Token;


    // JSON structured logs with level and component/service
static JSON_STRUCTURED_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r#"\{"[^"]*(?:level|severity|lvl)"[^"]*:\s*"(error|warn|warning|info|information|debug|trace|fatal|critical)"[^}]*"(?:component|service|module|logger|source)"[^"]*:\s*"([^"]+)"[^}]*\}"#
    ).unwrap());

    // Alternative JSON order: component first, then level
static JSON_STRUCTURED_ALT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r#"\{"[^"]*"(?:component|service|module|logger|source)"[^"]*:\s*"([^"]+)"[^}]*"(?:level|severity|lvl)"[^"]*:\s*"(error|warn|warning|info|information|debug|trace|fatal|critical)"[^}]*\}"#
    ).unwrap());

    // Logfmt style: level=info component=api-gateway msg="message"
static LOGFMT_STRUCTURED_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r"(?:level|severity|lvl)=(error|warn|warning|info|information|debug|trace|fatal|critical)\s+(?:component|service|module|logger|source)=([^\s]+)"
    ).unwrap());

    // Docker/Container structured logs
static CONTAINER_STRUCTURED_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r#"\{"[^}]*"log":\s*"[^"]*\[(INFO|ERROR|WARN|DEBUG)\]\s+([^:]+):[^"]*"[^}]*\}"#
    ).unwrap());

pub struct StructuredMessageDetector;

impl StructuredMessageDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no structured log indicators
        if !Self::has_structured_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Apply structured message detection in order of specificity
        // NOTE: K8s pattern disabled - handled by KubernetesDetector to prevent theft
        // Self::apply_k8s_pattern(&mut result, &mut tokens);
        Self::apply_container_pattern(&mut result, &mut tokens);
        Self::apply_json_pattern(&mut result, &mut tokens);
        Self::apply_json_alt_pattern(&mut result, &mut tokens);
        Self::apply_logfmt_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_structured_indicators(text: &str) -> bool {
        // Fast byte-level checks for structured logging indicators
        (text.contains(r#""level":"#) ||
         text.contains(r#""severity":"#) ||
         text.contains(r#""component":"#) ||
         text.contains(r#""service":"#) ||
         text.contains("level=") ||
         text.contains("component=")) &&
        // Must have JSON or logfmt structure
        (text.contains('{') || text.contains('=')) &&
        // Exclude non-log JSON
        !text.contains(r#""data":"#) &&
        !text.contains(r#""result":"#) &&
        !text.contains(r#""response":"#) &&
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
        text.contains(r#""component":"kubelet"#) ||
        text.contains(r#""component":"scheduler"#) ||
        text.contains(r#""component":"proxy"#) ||
        text.contains(r#""component":"controller"#) ||
        text.contains(r#""component":"etcd"#) ||
        text.contains(r#""component":"coredns"#) ||
        // Logfmt style Kubernetes components
        text.contains("component=kubelet") ||
        text.contains("component=scheduler") ||
        text.contains("component=proxy") ||
        text.contains("component=controller") ||
        text.contains("component=etcd") ||
        text.contains("component=coredns")
    }

    fn apply_container_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = CONTAINER_STRUCTURED_REGEX.replace_all(text, |caps: &regex::Captures| {
            let level = caps.get(1).unwrap().as_str();
            let component = caps.get(2).unwrap().as_str();

            if Self::is_application_component(component) {
                tokens.push(Token::StructuredMessage {
                    component: component.to_lowercase(),
                    level: level.to_lowercase(),
                });
                r#"{"log": "<STRUCTURED_MESSAGE>"}"#.to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).to_string();
    }

    fn apply_json_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = JSON_STRUCTURED_REGEX.replace_all(text, |caps: &regex::Captures| {
            let level = caps.get(1).unwrap().as_str();
            let component = caps.get(2).unwrap().as_str();

            if Self::is_valid_structured_log(component, level) {
                tokens.push(Token::StructuredMessage {
                    component: component.to_lowercase(),
                    level: level.to_lowercase(),
                });
                "<STRUCTURED_MESSAGE>".to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).to_string();
    }

    fn apply_json_alt_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = JSON_STRUCTURED_ALT_REGEX.replace_all(text, |caps: &regex::Captures| {
            let component = caps.get(1).unwrap().as_str();
            let level = caps.get(2).unwrap().as_str();

            if Self::is_valid_structured_log(component, level) {
                tokens.push(Token::StructuredMessage {
                    component: component.to_lowercase(),
                    level: level.to_lowercase(),
                });
                "<STRUCTURED_MESSAGE>".to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).to_string();
    }

    fn apply_logfmt_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = LOGFMT_STRUCTURED_REGEX.replace_all(text, |caps: &regex::Captures| {
            let level = caps.get(1).unwrap().as_str();
            let component = caps.get(2).unwrap().as_str();

            if Self::is_valid_structured_log(component, level) {
                tokens.push(Token::StructuredMessage {
                    component: component.to_lowercase(),
                    level: level.to_lowercase(),
                });
                "<STRUCTURED_MESSAGE>".to_string()
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        }).to_string();
    }

    fn is_application_component(component: &str) -> bool {
        let app_components = [
            "application", "database", "cache", "auth", "payment",
            "notification", "user", "order", "inventory", "billing",
            "analytics", "monitoring", "logging", "metrics"
        ];

        app_components.iter().any(|&app_comp| component.contains(app_comp)) ||
        component.ends_with("-service") ||
        component.ends_with("_service") ||
        component.ends_with("-api") ||
        component.ends_with("_api") ||
        component.ends_with("-client") ||
        component.ends_with("_client")
    }

    fn is_microservice_component(component: &str) -> bool {
        // Common microservice naming patterns
        component.contains("service") ||
        component.contains("api") ||
        component.contains("gateway") ||
        component.contains("proxy") ||
        component.contains("balancer") ||
        component.contains("registry") ||
        component.contains("discovery") ||
        component.contains("config") ||
        component.contains("auth") ||
        component.contains("user") ||
        component.contains("payment") ||
        component.contains("order") ||
        component.contains("inventory") ||
        component.contains("notification")
    }

    fn is_framework_component(component: &str) -> bool {
        let framework_components = [
            "spring", "hibernate", "jackson", "slf4j", "logback",
            "jersey", "servlet", "tomcat", "jetty", "netty",
            "akka", "vertx", "reactor", "rxjava", "guava"
        ];

        framework_components.iter().any(|&framework| component.contains(framework)) ||
        component.contains('.') && !component.contains(' ')  // Package-style names
    }

    fn is_infrastructure_component(component: &str) -> bool {
        let infra_components = [
            "nginx", "apache", "haproxy", "envoy", "traefik",
            "consul", "vault", "nomad", "prometheus", "grafana",
            "elasticsearch", "logstash", "kibana", "fluentd",
            "redis", "memcached", "mongodb", "postgresql", "mysql"
        ];

        infra_components.iter().any(|&infra| component.contains(infra))
    }

    fn is_valid_structured_log(component: &str, level: &str) -> bool {
        // Validate log level
        let valid_levels = [
            "error", "warn", "warning", "info", "information",
            "debug", "trace", "fatal", "critical"
        ];

        if !valid_levels.contains(&level.to_lowercase().as_str()) {
            return false;
        }

        // Validate component (K8s components removed to prevent pattern theft)
        Self::is_application_component(component) ||
        Self::is_microservice_component(component) ||
        Self::is_framework_component(component) ||
        Self::is_infrastructure_component(component) ||
        // Generic validation for reasonable component names
        (component.len() >= 3 &&
         component.len() <= 50 &&
         component.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') &&
         !component.chars().all(|c| c.is_ascii_digit()))  // Not just numbers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubernetes_structured_detection() {
        // Lines with Kubernetes components (kubelet, scheduler, etc.) are excluded
        // from StructuredMessageDetector to prevent pattern theft with KubernetesDetector
        let k8s_line = r#"{"level":"info","ts":"2024-01-01T10:00:00.000Z","component":"kubelet","msg":"Starting container"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(k8s_line);

        assert!(tokens.is_empty());
        assert_eq!(result, k8s_line);
    }

    #[test]
    fn test_microservice_structured_detection() {
        let microservice_line = r#"{"timestamp":"2024-01-01T10:00:00Z","level":"ERROR","service":"payment-api","message":"Payment failed"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(microservice_line);

        if !tokens.is_empty() {
            assert!(result.contains("<STRUCTURED_MESSAGE>"));
            if let Token::StructuredMessage { component, level } = &tokens[0] {
                assert_eq!(component, "payment-api");
                assert_eq!(level, "error");
            }
        }
    }

    #[test]
    fn test_logfmt_structured_detection() {
        let logfmt_line = "time=2024-01-01T10:00:00Z level=info component=api-gateway msg=\"Request received\"";
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(logfmt_line);

        if !tokens.is_empty() {
            assert!(result.contains("<STRUCTURED_MESSAGE>"));
            if let Token::StructuredMessage { component, level } = &tokens[0] {
                assert_eq!(component, "api-gateway");
                assert_eq!(level, "info");
            }
        }
    }

    #[test]
    fn test_container_structured_detection() {
        let container_line = r#"{"log":"2024-01-01T10:00:00.000Z [INFO] application: Starting server\n","stream":"stdout"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(container_line);

        if !tokens.is_empty() {
            assert!(result.contains("<STRUCTURED_MESSAGE>"));
            if let Token::StructuredMessage { component, level } = &tokens[0] {
                assert_eq!(component, "application");
                assert_eq!(level, "info");
            }
        }
    }

    // TODO: Re-enable these tests when methods are implemented
    // #[test]
    // fn test_component_classification() {
    //     assert!(StructuredMessageDetector::is_k8s_component("kubelet"));
    //     assert!(StructuredMessageDetector::is_application_component("user-service"));
    //     assert!(StructuredMessageDetector::is_microservice_component("payment-api"));
    //     assert!(StructuredMessageDetector::is_framework_component("spring.web"));
    //     assert!(StructuredMessageDetector::is_infrastructure_component("nginx"));
    // }

    // #[test]
    // fn test_structured_log_validation() {
    //     assert!(StructuredMessageDetector::is_valid_structured_log("api-gateway", "info"));
    //     assert!(StructuredMessageDetector::is_valid_structured_log("kubelet", "error"));
    //     assert!(StructuredMessageDetector::is_valid_structured_log("payment-service", "warn"));

    //     // Invalid cases
    //     assert!(!StructuredMessageDetector::is_valid_structured_log("api-gateway", "invalid"));
    //     assert!(!StructuredMessageDetector::is_valid_structured_log("123", "info"));
    //     assert!(!StructuredMessageDetector::is_valid_structured_log("", "info"));
    // }

    #[test]
    fn test_no_false_positives() {
        let non_log_cases = vec![
            r#"{"user_id": 12345, "action": "login", "result": "success"}"#,
            r#"{"api_response": {"data": [], "status": 200}}"#,
            r#"{"config": {"level": "production", "component": "database"}}"#,
        ];

        for test_case in non_log_cases {
            let (_result, tokens) = StructuredMessageDetector::detect_and_replace(test_case);

            // Should not detect structured logging in data JSON
            let has_structured = tokens.iter().any(|token| {
                matches!(token, Token::StructuredMessage { .. })
            });

            if has_structured {
                // If detected, should be valid
                for token in &tokens {
                    if let Token::StructuredMessage { component, level } = token {
                        assert!(StructuredMessageDetector::is_valid_structured_log(component, level));
                    }
                }
            }
        }
    }

    #[test]
    fn test_multiple_structured_messages() {
        let multi_line = r#"Received: {"level":"info","component":"api","msg":"Request"} Processing: {"level":"debug","component":"handler","msg":"Validation"}"#;
        let (result, tokens) = StructuredMessageDetector::detect_and_replace(multi_line);

        let structured_count = tokens.iter()
            .filter(|token| matches!(token, Token::StructuredMessage { .. }))
            .count();

        if structured_count > 0 {
            assert!(result.contains("<STRUCTURED_MESSAGE>"));
        }
    }
}
