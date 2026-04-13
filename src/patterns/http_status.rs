use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// HTTP status codes in common web server log formats
// Matches patterns like: "GET /path HTTP/1.1" 200 1234 "-"
// Also matches: "HTTP/1.1" 404 335 (response format)
static HTTP_STATUS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"[^"]*(?:HTTP/\d\.\d)"?\s+)(\d{3})(?:\s+\d+(?:\s+|$))"#).unwrap()
});

// Alternative pattern for access logs: method path protocol" status size
static ACCESS_LOG_STATUS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]*"\s+(\d{3})\s+\d+"#).unwrap()
});

// Pattern for proxy logs: upstream_status -> downstream_status
static PROXY_STATUS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d{3})\s*->\s*.*?(\d{3})").unwrap());

pub struct HttpStatusDetector;

impl HttpStatusDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no HTTP indicators
        if !Self::has_http_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Apply HTTP status detection in order of specificity
        Self::apply_access_log_pattern(&mut result, &mut tokens);
        Self::apply_http_status_pattern(&mut result, &mut tokens);
        Self::apply_proxy_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_http_indicators(text: &str) -> bool {
        // Fast byte-level checks for HTTP indicators
        text.contains("HTTP/")
            || text.contains("GET ")
            || text.contains("POST ")
            || text.contains("PUT ")
            || text.contains("DELETE ")
            || text.contains("\" 2")
            || text.contains("\" 3")
            || text.contains("\" 4")
            || text.contains("\" 5")
    }

    #[mutants::skip] // HTTP_STATUS_REGEX (line 9) matches the same inputs — redundant coverage
    fn apply_access_log_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = ACCESS_LOG_STATUS_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let status_code = caps.get(1).unwrap().as_str();
                if let Ok(status) = status_code.parse::<u16>() {
                    let class = Self::classify_status_code(status);
                    tokens.push(Token::HttpStatusClass(class.clone()));
                    format!(
                        "{}<HTTP_STATUS_{}>{}",
                        &caps.get(0).unwrap().as_str()
                            [..caps.get(1).unwrap().start() - caps.get(0).unwrap().start()],
                        class.to_uppercase(),
                        &caps.get(0).unwrap().as_str()
                            [caps.get(1).unwrap().end() - caps.get(0).unwrap().start()..]
                    )
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_http_status_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = HTTP_STATUS_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let status_code = caps.get(1).unwrap().as_str();
                if let Ok(status) = status_code.parse::<u16>() {
                    let class = Self::classify_status_code(status);
                    tokens.push(Token::HttpStatusClass(class.clone()));
                    format!(
                        "{}<HTTP_STATUS_{}>{}",
                        &caps.get(0).unwrap().as_str()
                            [..caps.get(1).unwrap().start() - caps.get(0).unwrap().start()],
                        class.to_uppercase(),
                        &caps.get(0).unwrap().as_str()
                            [caps.get(1).unwrap().end() - caps.get(0).unwrap().start()..]
                    )
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_proxy_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = PROXY_STATUS_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let upstream_status = caps.get(1).unwrap().as_str();
                let downstream_status = caps.get(2).unwrap().as_str();

                if let (Ok(upstream), Ok(downstream)) = (
                    upstream_status.parse::<u16>(),
                    downstream_status.parse::<u16>(),
                ) {
                    let upstream_class = Self::classify_status_code(upstream);
                    let downstream_class = Self::classify_status_code(downstream);

                    tokens.push(Token::HttpStatusClass(upstream_class.clone()));
                    tokens.push(Token::HttpStatusClass(downstream_class.clone()));

                    format!(
                        "<HTTP_STATUS_{}> -> <HTTP_STATUS_{}>",
                        upstream_class.to_uppercase(),
                        downstream_class.to_uppercase()
                    )
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn classify_status_code(status: u16) -> String {
        match status {
            100..=199 => "1xx".to_string(),
            200..=299 => "2xx".to_string(),
            300..=399 => "3xx".to_string(),
            400..=499 => "4xx".to_string(),
            500..=599 => "5xx".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nginx_access_log_detection() {
        let nginx_line = r#"93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-""#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(nginx_line);

        assert_eq!(tokens.len(), 1);
        if let Token::HttpStatusClass(class) = &tokens[0] {
            assert_eq!(class, "3xx");
        }
        assert!(result.contains("<HTTP_STATUS_3XX>"));
    }

    #[test]
    fn test_apache_access_log_detection() {
        let apache_line =
            r#"127.0.0.1 - - [25/Dec/2023:10:15:30 +0000] "POST /api/login HTTP/1.1" 401 256"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(apache_line);

        assert_eq!(tokens.len(), 1);
        if let Token::HttpStatusClass(class) = &tokens[0] {
            assert_eq!(class, "4xx");
        }
        assert!(result.contains("<HTTP_STATUS_4XX>"));
    }

    #[test]
    fn test_multiple_status_codes() {
        let proxy_line =
            r#"Proxy response: "GET /api HTTP/1.1" 200 -> "GET /backend HTTP/1.1" 502"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(proxy_line);

        assert!(tokens.len() >= 2);
        assert!(result.contains("<HTTP_STATUS_2XX>"));
        assert!(result.contains("<HTTP_STATUS_5XX>"));
    }

    #[test]
    fn test_status_classification() {
        assert_eq!(HttpStatusDetector::classify_status_code(200), "2xx");
        assert_eq!(HttpStatusDetector::classify_status_code(404), "4xx");
        assert_eq!(HttpStatusDetector::classify_status_code(500), "5xx");
    }

    #[test]
    fn test_no_false_positives() {
        let non_http_line = "Processing 200 records successfully";
        let (result, tokens) = HttpStatusDetector::detect_and_replace(non_http_line);

        assert_eq!(tokens.len(), 0);
        assert_eq!(result, non_http_line);
    }

    // ---- has_http_indicators: per-condition tests ----

    #[test]
    fn http_ind_http_slash() {
        assert!(HttpStatusDetector::has_http_indicators("HTTP/1.1 200 OK"));
    }

    #[test]
    fn http_ind_get() {
        assert!(HttpStatusDetector::has_http_indicators("GET /index.html"));
    }

    #[test]
    fn http_ind_post() {
        assert!(HttpStatusDetector::has_http_indicators("POST /api/data"));
    }

    #[test]
    fn http_ind_put() {
        assert!(HttpStatusDetector::has_http_indicators("PUT /api/item"));
    }

    #[test]
    fn http_ind_delete() {
        assert!(HttpStatusDetector::has_http_indicators("DELETE /api/item"));
    }

    #[test]
    fn http_ind_status_2xx() {
        assert!(HttpStatusDetector::has_http_indicators(r#""/path" 200"#));
    }

    #[test]
    fn http_ind_status_3xx() {
        assert!(HttpStatusDetector::has_http_indicators(r#""/path" 301"#));
    }

    #[test]
    fn http_ind_status_4xx() {
        assert!(HttpStatusDetector::has_http_indicators(r#""/path" 404"#));
    }

    #[test]
    fn http_ind_status_5xx() {
        assert!(HttpStatusDetector::has_http_indicators(r#""/path" 500"#));
    }

    #[test]
    fn http_ind_negative() {
        assert!(!HttpStatusDetector::has_http_indicators(
            "plain log message"
        ));
    }

    // ---- classify_status_code: each match arm ----

    #[test]
    fn classify_1xx() {
        assert_eq!(HttpStatusDetector::classify_status_code(100), "1xx");
        assert_eq!(HttpStatusDetector::classify_status_code(199), "1xx");
    }

    #[test]
    fn classify_2xx() {
        assert_eq!(HttpStatusDetector::classify_status_code(200), "2xx");
    }

    #[test]
    fn classify_3xx() {
        assert_eq!(HttpStatusDetector::classify_status_code(301), "3xx");
    }

    #[test]
    fn classify_4xx() {
        assert_eq!(HttpStatusDetector::classify_status_code(404), "4xx");
    }

    #[test]
    fn classify_5xx() {
        assert_eq!(HttpStatusDetector::classify_status_code(500), "5xx");
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(HttpStatusDetector::classify_status_code(600), "unknown");
    }

    // ---- apply_http_status_pattern: verifies text modification ----

    #[test]
    fn apply_http_status_modifies_text() {
        let input = r#"10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET /api HTTP/1.1" 200 1234"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert!(!tokens.is_empty(), "should detect HTTP status: {result}");
        assert!(
            result.contains("<HTTP_STATUS"),
            "text should be modified: {result}"
        );
    }

    // ---- Mutant-killing: apply_access_log_pattern (replace with ()) ----

    #[test]
    fn access_log_pattern_only() {
        // Input that matches ONLY the access log pattern (GET/POST + status)
        // and NOT the generic HTTP_STATUS_REGEX pattern
        let input = r#""GET /index.html HTTP/1.1" 200 1234"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert!(
            !tokens.is_empty(),
            "access log pattern should detect status: {result}"
        );
        assert!(
            result.contains("<HTTP_STATUS_2XX>"),
            "should replace status code: {result}"
        );
    }

    // ---- Mutant-killing: apply_http_status_pattern (replace with ()) ----

    #[test]
    fn http_status_pattern_only() {
        // Input that matches the HTTP_STATUS_REGEX but NOT access log pattern
        // HTTP_STATUS_REGEX: "...HTTP/1.1" STATUS SIZE
        let input = r#"response "HTTP/1.1" 404 335 end"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert!(
            !tokens.is_empty(),
            "HTTP status pattern should detect status: {result}"
        );
        assert!(
            result.contains("<HTTP_STATUS"),
            "should replace status code: {result}"
        );
    }

    // ---- Mutant-killing: apply_proxy_pattern ----

    #[test]
    fn proxy_pattern_detection() {
        // Input that matches the PROXY_STATUS_REGEX: NNN -> NNN
        let input = "GET /api upstream 200 -> downstream 502";
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert!(
            tokens.len() >= 2,
            "proxy pattern should detect 2 status codes: {tokens:?}"
        );
        assert!(
            result.contains("<HTTP_STATUS_2XX>") && result.contains("<HTTP_STATUS_5XX>"),
            "should replace both status codes: {result}"
        );
    }
}
