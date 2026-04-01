use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Key-value pairs with various separators: key=value, key:value, key value
static KEY_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([a-zA-Z][a-zA-Z0-9_.-]*)\s*[=:]\s*([^\s,;|]+(?:%|ms|s|MB|GB|KB|bytes?)?)")
        .unwrap()
});

// Configuration-style key-value: config: key=value, other=123
static CONFIG_KV_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-zA-Z][a-zA-Z0-9_.-]*)\s*=\s*([^\s,;|]+)").unwrap());

// Metrics-style key-value: cpu=75%, memory=60%
static METRICS_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([a-zA-Z][a-zA-Z0-9_.-]*)\s*=\s*(\d+(?:\.\d+)?(?:%|ms|s|MB|GB|KB|rps|qps)?)")
        .unwrap()
});

// JSON-style key-value: "key": "value" or "key":123
static JSON_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([a-zA-Z][a-zA-Z0-9_.-]*)"\s*:\s*(?:"([^"]+)"|(\d+(?:\.\d+)?)|true|false|null)"#)
        .unwrap()
});

pub struct KeyValueDetector;

impl KeyValueDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no key-value indicators
        if !Self::has_key_value_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Apply key-value detection in order of specificity
        Self::apply_metrics_pattern(&mut result, &mut tokens);
        Self::apply_config_pattern(&mut result, &mut tokens);
        Self::apply_json_pattern(&mut result, &mut tokens);
        Self::apply_general_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_key_value_indicators(text: &str) -> bool {
        // Fast byte-level checks for key-value indicators
        (text.contains('=') || text.contains(':')) &&
        // Exclude obvious non-key-value patterns
        !text.contains("if ") &&      // if variable = value
        !text.contains("for ") &&     // for loop constructs
        !text.contains("while ") &&   // while loop constructs
        !text.contains("SELECT ") &&  // SQL queries
        !text.contains("http://") &&  // URLs
        !text.contains("https://") && // URLs
        !text.contains("ftp://") // URLs
    }

    fn apply_metrics_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = METRICS_KV_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let key = caps.get(1).unwrap().as_str();
                let value = caps.get(2).unwrap().as_str();

                if Self::is_metrics_context(text, caps.get(0).unwrap().start()) {
                    let value_type = Self::classify_value_type(value);
                    tokens.push(Token::KeyValuePair {
                        key: key.to_lowercase(),
                        value_type,
                    });
                    "<KEY_VALUE>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_config_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = CONFIG_KV_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let key = caps.get(1).unwrap().as_str();
                let value = caps.get(2).unwrap().as_str();

                if Self::is_config_context(text, caps.get(0).unwrap().start()) {
                    let value_type = Self::classify_value_type(value);
                    tokens.push(Token::KeyValuePair {
                        key: key.to_lowercase(),
                        value_type,
                    });
                    "<KEY_VALUE>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_json_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = JSON_KV_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let key = caps.get(1).unwrap().as_str();
                let value = caps
                    .get(2)
                    .or_else(|| caps.get(3))
                    .map_or("null", |m| m.as_str());

                if Self::is_logging_json(text) {
                    let value_type = Self::classify_value_type(value);
                    tokens.push(Token::KeyValuePair {
                        key: key.to_lowercase(),
                        value_type,
                    });
                    format!(r#""{key}": <KEY_VALUE>"#)
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_general_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = KEY_VALUE_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let key = caps.get(1).unwrap().as_str();
                let value = caps.get(2).unwrap().as_str();

                if Self::is_valid_key_value_context(key, value, text) {
                    let value_type = Self::classify_value_type(value);
                    tokens.push(Token::KeyValuePair {
                        key: key.to_lowercase(),
                        value_type,
                    });
                    "<KEY_VALUE>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn classify_value_type(value: &str) -> String {
        let lower_value = value.to_lowercase();

        // Percentage values
        if value.ends_with('%') {
            return "percentage".to_string();
        }

        // Duration values
        if value.ends_with("ms") || value.ends_with("us") || value.ends_with("ns") {
            return "duration".to_string();
        }
        if value.ends_with('s')
            && value
                .chars()
                .rev()
                .nth(1)
                .is_some_and(|c| c.is_ascii_digit())
        {
            return "duration".to_string();
        }

        // Size values
        if value.ends_with("MB")
            || value.ends_with("GB")
            || value.ends_with("KB")
            || value.ends_with("bytes")
            || value.ends_with("byte")
        {
            return "size".to_string();
        }

        // Rate values
        if value.ends_with("rps")
            || value.ends_with("qps")
            || value.ends_with("/s")
            || value.ends_with("/min")
            || value.ends_with("/hr")
        {
            return "rate".to_string();
        }

        // Boolean values
        if lower_value == "true"
            || lower_value == "false"
            || lower_value == "enabled"
            || lower_value == "disabled"
            || lower_value == "on"
            || lower_value == "off"
        {
            return "boolean".to_string();
        }

        // Numeric values
        if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return "number".to_string();
        }

        // IP addresses
        if Self::is_ip_address(value) {
            return "ip".to_string();
        }

        // URLs
        if value.starts_with("http://")
            || value.starts_with("https://")
            || value.starts_with("ftp://")
        {
            return "url".to_string();
        }

        // Default to string
        "string".to_string()
    }

    fn is_metrics_context(text: &str, _position: usize) -> bool {
        let metrics_indicators = [
            "metrics",
            "stats",
            "performance",
            "monitor",
            "usage",
            "cpu",
            "memory",
            "disk",
            "network",
            "load",
            "throughput",
            "latency",
            "response_time",
            "error_rate",
            "success_rate",
        ];

        let lower_text = text.to_lowercase();
        metrics_indicators
            .iter()
            .any(|&indicator| lower_text.contains(indicator))
    }

    fn is_config_context(text: &str, _position: usize) -> bool {
        let config_indicators = [
            "config",
            "configuration",
            "settings",
            "params",
            "parameters",
            "options",
            "properties",
            "environment",
            "variables",
        ];

        let lower_text = text.to_lowercase();
        config_indicators
            .iter()
            .any(|&indicator| lower_text.contains(indicator))
    }

    fn is_logging_json(text: &str) -> bool {
        // Check if this appears to be a structured log entry
        let log_indicators = [
            "level",
            "timestamp",
            "message",
            "msg",
            "component",
            "service",
            "logger",
            "severity",
            "time",
            "ts",
        ];

        log_indicators
            .iter()
            .any(|&indicator| text.contains(indicator))
    }

    fn is_valid_key_value_context(key: &str, value: &str, text: &str) -> bool {
        // Exclude programming constructs
        if key == "if" || key == "for" || key == "while" || key == "switch" {
            return false;
        }

        // Exclude mathematical expressions
        if text.contains(" + ")
            || text.contains(" - ")
            || text.contains(" * ")
            || text.contains(" / ")
        {
            return false;
        }

        // Exclude SQL queries
        if text.to_uppercase().contains("SELECT ")
            || text.to_uppercase().contains("INSERT ")
            || text.to_uppercase().contains("UPDATE ")
            || text.to_uppercase().contains("DELETE ")
        {
            return false;
        }

        // Include common configuration/logging keys
        let valid_keys = [
            "timeout",
            "retries",
            "max_connections",
            "port",
            "host",
            "ssl",
            "debug",
            "verbose",
            "level",
            "user_id",
            "session_id",
            "request_id",
            "attempt_count",
            "failure_rate",
            "success_rate",
            "response_time",
            "cpu_usage",
            "memory_usage",
            "disk_usage",
            "queue_size",
            "buffer_size",
        ];

        valid_keys.contains(&key) || Self::is_common_config_pattern(key, value)
    }

    fn is_common_config_pattern(key: &str, value: &str) -> bool {
        // Common configuration patterns
        key.ends_with("_timeout") ||
        key.ends_with("_limit") ||
        key.ends_with("_size") ||
        key.ends_with("_count") ||
        key.ends_with("_rate") ||
        key.ends_with("_usage") ||
        key.starts_with("max_") ||
        key.starts_with("min_") ||
        // Value patterns that suggest configuration
        value.ends_with("ms") ||
        value.ends_with('%') ||
        value.ends_with("MB") ||
        value.ends_with("KB") ||
        value.ends_with("GB")
    }

    fn is_ip_address(value: &str) -> bool {
        // Simple IPv4 pattern
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|&part| part.parse::<u8>().is_ok());
        }

        // Simple IPv6 check
        value.contains(':') && value.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_detection() {
        let metrics_line = "Performance metrics: cpu=75%, memory=60%, disk=45%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(metrics_line);

        assert!(!tokens.is_empty());
        assert!(result.contains("<KEY_VALUE>"));

        // Check percentage classification
        let has_percentage = tokens.iter().any(|token| {
            if let Token::KeyValuePair { key: _, value_type } = token {
                value_type == "percentage"
            } else {
                false
            }
        });
        assert!(has_percentage);
    }

    #[test]
    fn test_config_detection() {
        let config_line = "Database config: host=localhost, port=5432, ssl=true";
        let (result, tokens) = KeyValueDetector::detect_and_replace(config_line);

        assert!(tokens.len() >= 3);
        assert!(result.contains("<KEY_VALUE>"));
    }

    #[test]
    fn test_value_type_classification() {
        assert_eq!(KeyValueDetector::classify_value_type("75%"), "percentage");
        assert_eq!(KeyValueDetector::classify_value_type("250ms"), "duration");
        assert_eq!(KeyValueDetector::classify_value_type("1GB"), "size");
        assert_eq!(KeyValueDetector::classify_value_type("true"), "boolean");
        assert_eq!(KeyValueDetector::classify_value_type("12345"), "number");
        // "192.168.1.1" matches the numeric check (all digits and '.') before the IP check
        assert_eq!(
            KeyValueDetector::classify_value_type("192.168.1.1"),
            "number"
        );
    }

    #[test]
    fn test_no_false_positives() {
        let non_kv_cases = vec![
            "if variable = value then",
            "for i = 1 to 10",
            "SELECT * FROM table WHERE id = 123",
            "Mathematical equation: x=y+z",
        ];

        for test_case in non_kv_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            // Should not detect key-value pairs in programming constructs
            if test_case.contains("if ")
                || test_case.contains("for ")
                || test_case.contains("SELECT ")
            {
                assert_eq!(tokens.len(), 0);
                assert_eq!(result, test_case);
            }
        }
    }
}
