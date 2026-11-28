use super::Token;
use regex::Regex;
use std::sync::LazyLock;

const STATUS_CODE: &str = r"(?P<status>\d{3})";
const WHOLE_STATUS_CODE: &str = r"\b[1-5]\d{2}\b";
const ARROW_AND_TEXT_BETWEEN: &str = r"\s*->\s*.*?";
const HTTP_METHODS: &str = "GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH";
const PREFILTER_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];

static QUOTED_PROTOCOL_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?:"[^"]*(?:HTTP/\d\.\d)"?\s+){STATUS_CODE}(?:\s+(?:\d+|-)(?:\s+|$))"#
    ))
    .unwrap()
});

static ACCESS_LOG_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#""(?:{HTTP_METHODS})\s+[^"]*"\s+{STATUS_CODE}\s+(?:\d+|-(?:\s|$))"#
    ))
    .unwrap()
});

static WHOLE_STATUS: LazyLock<Regex> = LazyLock::new(|| Regex::new(WHOLE_STATUS_CODE).unwrap());

static PROXY_STATUS_ARROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<upstream>{WHOLE_STATUS_CODE})(?P<between>{ARROW_AND_TEXT_BETWEEN})(?P<downstream>{WHOLE_STATUS_CODE})"
    ))
    .unwrap()
});

pub struct HttpStatusDetector;

impl HttpStatusDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::has_http_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        Self::apply_status_pattern(&mut result, &mut tokens, &ACCESS_LOG_STATUS);
        Self::apply_status_pattern(&mut result, &mut tokens, &QUOTED_PROTOCOL_STATUS);
        Self::apply_proxy_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    fn has_http_indicators(text: &str) -> bool {
        text.contains("HTTP/")
            || PREFILTER_METHODS
                .iter()
                .any(|method| Self::followed_by_whitespace(text, method))
            || Self::has_quote_then_status_digit(text)
    }

    fn followed_by_whitespace(text: &str, needle: &str) -> bool {
        text.match_indices(needle)
            .any(|(i, _)| text[i + needle.len()..].starts_with(char::is_whitespace))
    }

    fn has_quote_then_status_digit(text: &str) -> bool {
        text.match_indices('"').any(|(i, _)| {
            let rest = &text[i + 1..];
            let digits = rest.trim_start();
            digits.len() < rest.len() && digits.starts_with(|c: char| ('1'..='5').contains(&c))
        })
    }

    fn apply_status_pattern(text: &mut String, tokens: &mut Vec<Token>, regex: &Regex) {
        *text = regex
            .replace_all(text, |caps: &regex::Captures| {
                let status_code = caps.name("status").unwrap();
                if let Ok(status) = status_code.as_str().parse::<u16>() {
                    let class = Self::classify_status_code(status);
                    tokens.push(Token::HttpStatusClass(class.clone()));
                    let whole = caps.get(0).unwrap();
                    format!(
                        "{}<HTTP_STATUS_{}>{}",
                        &whole.as_str()[..status_code.start() - whole.start()],
                        class.to_uppercase(),
                        &whole.as_str()[status_code.end() - whole.start()..]
                    )
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn apply_proxy_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        let source: &str = text;
        let folded = PROXY_STATUS_ARROW
            .replace_all(source, |caps: &regex::Captures| {
                let upstream_status = &caps["upstream"];
                let between = &caps["between"];
                let downstream_status = &caps["downstream"];
                let after = &source[caps.get(0).unwrap().end()..];
                if between.contains("<HTTP_STATUS_") || WHOLE_STATUS.is_match(after) {
                    return caps[0].to_string();
                }

                if let (Ok(upstream), Ok(downstream)) = (
                    upstream_status.parse::<u16>(),
                    downstream_status.parse::<u16>(),
                ) {
                    let upstream_class = Self::classify_status_code(upstream);
                    let downstream_class = Self::classify_status_code(downstream);

                    tokens.push(Token::HttpStatusClass(upstream_class.clone()));
                    tokens.push(Token::HttpStatusClass(downstream_class.clone()));

                    format!(
                        "<HTTP_STATUS_{}>{between}<HTTP_STATUS_{}>",
                        upstream_class.to_uppercase(),
                        downstream_class.to_uppercase()
                    )
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
        *text = folded;
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

    #[test]
    fn access_log_line_folds_status() {
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

    #[test]
    fn access_log_pattern_only() {
        let input = r#""GET /index.html" 200 1234"#;
        assert!(
            !QUOTED_PROTOCOL_STATUS.is_match(input),
            "no protocol, so only the access-log pattern can match"
        );
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert_eq!(result, r#""GET /index.html" <HTTP_STATUS_2XX> 1234"#);
        assert_eq!(tokens, vec![Token::HttpStatusClass("2xx".into())]);
    }

    #[test]
    fn the_access_log_pass_runs_before_the_quoted_protocol_pass() {
        let input = r#""GET /a" 404 1 "HTTP/1.1" 200 2 end"#;
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert_eq!(
            result,
            r#""GET /a" <HTTP_STATUS_4XX> 1 "HTTP/1.1" <HTTP_STATUS_2XX> 2 end"#
        );
        assert_eq!(
            tokens,
            vec![
                Token::HttpStatusClass("4xx".into()),
                Token::HttpStatusClass("2xx".into()),
            ],
            "the access-log token comes first because its pass runs first"
        );
    }

    #[test]
    fn http_status_pattern_only() {
        let input = r#"response "HTTP/1.1" 404 335 end"#;
        assert!(
            !ACCESS_LOG_STATUS.is_match(input),
            "a bare quoted protocol with no method matches only the quoted-protocol pattern"
        );
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

    #[test]
    fn proxy_pattern_detection() {
        let input = "GET /api upstream 200 -> downstream 502";
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert!(
            tokens.len() >= 2,
            "proxy pattern should detect 2 status codes: {tokens:?}"
        );
        assert_eq!(
            result, "GET /api upstream <HTTP_STATUS_2XX> -> downstream <HTTP_STATUS_5XX>",
            "both codes fold and the words between them stay"
        );
    }

    #[test]
    fn proxy_pattern_takes_whole_codes_and_keeps_the_words_between() {
        let input = "GET /api id 12345 -> 67890 moved";
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert_eq!(result, input, "12345 -> 67890 holds no status code");
        assert!(tokens.is_empty(), "{tokens:?}");

        let (miss, _) = HttpStatusDetector::detect_and_replace(
            "GET /api upstream 502 -> cache miss on node 7 then 200",
        );
        assert_eq!(
            miss,
            "GET /api upstream <HTTP_STATUS_5XX> -> cache miss on node 7 then <HTTP_STATUS_2XX>"
        );
    }

    #[test]
    fn a_quote_needs_whitespace_then_a_status_digit() {
        assert!(!HttpStatusDetector::has_quote_then_status_digit(
            r#"x "200 y"#
        ));
        assert!(!HttpStatusDetector::has_quote_then_status_digit(
            r#""/p" abc"#
        ));
        assert!(HttpStatusDetector::has_quote_then_status_digit(
            "\"/p\"\t404"
        ));
    }

    #[test]
    fn a_tab_separated_head_request_folds_its_status() {
        let (result, tokens) = HttpStatusDetector::detect_and_replace("\"HEAD /x\"\t404\t1");
        assert_eq!(result, "\"HEAD /x\"\t<HTTP_STATUS_4XX>\t1");
        assert_eq!(tokens, vec![Token::HttpStatusClass("4xx".into())]);
    }

    #[test]
    fn a_dash_byte_field_still_marks_an_access_log_status() {
        let (result, _) = HttpStatusDetector::detect_and_replace(r#""GET /cached" 304 -"#);
        assert_eq!(result, r#""GET /cached" <HTTP_STATUS_3XX> -"#);
    }

    #[test]
    fn a_number_after_a_folded_status_is_not_a_proxy_downstream() {
        let input = r#"upstream 200 -> "GET /backend" 502 123"#;
        let (result, _) = HttpStatusDetector::detect_and_replace(input);
        assert_eq!(
            result,
            r#"upstream 200 -> "GET /backend" <HTTP_STATUS_5XX> 123"#
        );
    }

    #[test]
    fn two_status_shaped_numbers_after_an_arrow_leave_the_arrow_unfolded() {
        let input = "GET /api 502 -> node 123 returned 200";
        let (result, tokens) = HttpStatusDetector::detect_and_replace(input);
        assert_eq!(result, input);
        assert!(tokens.is_empty(), "{tokens:?}");
    }
}
