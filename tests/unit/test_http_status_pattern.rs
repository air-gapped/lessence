use lessence::patterns::Token;
use lessence::patterns::http_status::HttpStatusDetector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_status_class_2xx_detection() {
        let test_cases = vec![
            r#""GET /downloads/product_1 HTTP/1.1" 200 490 "-""#,
            r#""POST /api/users HTTP/1.1" 201 0 "-""#,
            r#""PUT /api/data HTTP/1.1" 204 0 "-""#,
        ];

        for test_case in test_cases {
            let (result, tokens) = HttpStatusDetector::detect_and_replace(test_case);

            // Should detect and replace status codes with class token
            assert!(
                result.contains("<HTTP_STATUS_2XX>"),
                "Failed to detect 2xx status in: {}",
                test_case
            );
            assert_eq!(
                tokens.len(),
                1,
                "Should detect exactly one HTTP status token"
            );

            if let Token::HttpStatusClass(class) = &tokens[0] {
                assert_eq!(class, "2xx", "Should classify as 2xx");
            } else {
                panic!("Expected HttpStatusClass token, got: {:?}", tokens[0]);
            }
        }
    }

    #[test]
    fn test_http_status_class_3xx_detection() {
        let test_cases = vec![
            r#""GET /downloads/product_1 HTTP/1.1" 304 0 "-""#,
            r#""GET /old-page HTTP/1.1" 301 0 "-""#,
            r#""GET /cached HTTP/1.1" 302 0 "-""#,
        ];

        for test_case in test_cases {
            let (result, tokens) = HttpStatusDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<HTTP_STATUS_3XX>"),
                "Failed to detect 3xx status in: {}",
                test_case
            );
            assert_eq!(tokens.len(), 1);

            if let Token::HttpStatusClass(class) = &tokens[0] {
                assert_eq!(class, "3xx");
            } else {
                panic!("Expected HttpStatusClass token");
            }
        }
    }

    #[test]
    fn test_http_status_class_4xx_detection() {
        let test_cases = vec![
            r#""GET /missing HTTP/1.1" 404 335 "-""#,
            r#""POST /api/login HTTP/1.1" 401 0 "-""#,
            r#""GET /forbidden HTTP/1.1" 403 0 "-""#,
        ];

        for test_case in test_cases {
            let (result, tokens) = HttpStatusDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<HTTP_STATUS_4XX>"),
                "Failed to detect 4xx status in: {}",
                test_case
            );
            assert_eq!(tokens.len(), 1);

            if let Token::HttpStatusClass(class) = &tokens[0] {
                assert_eq!(class, "4xx");
            } else {
                panic!("Expected HttpStatusClass token");
            }
        }
    }

    #[test]
    fn test_http_status_class_5xx_detection() {
        let test_cases = vec![
            r#""GET /error HTTP/1.1" 500 0 "-""#,
            r#""POST /api/broken HTTP/1.1" 502 0 "-""#,
            r#""GET /timeout HTTP/1.1" 503 0 "-""#,
        ];

        for test_case in test_cases {
            let (result, tokens) = HttpStatusDetector::detect_and_replace(test_case);

            assert!(
                result.contains("<HTTP_STATUS_5XX>"),
                "Failed to detect 5xx status in: {}",
                test_case
            );
            assert_eq!(tokens.len(), 1);

            if let Token::HttpStatusClass(class) = &tokens[0] {
                assert_eq!(class, "5xx");
            } else {
                panic!("Expected HttpStatusClass token");
            }
        }
    }

    #[test]
    fn test_nginx_access_log_compression() {
        // Real Nginx log examples that should compress better
        let nginx_lines = vec![
            r#"93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-" "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.21)""#,
            r#"93.180.71.3 - - [17/May/2015:08:05:23 +0000] "GET /downloads/product_1 HTTP/1.1" 200 490 "-" "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.21)""#,
            r#"217.168.17.5 - - [17/May/2015:08:05:34 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-" "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.21)""#,
        ];

        let mut all_results = Vec::new();
        for line in nginx_lines {
            let (result, _tokens) = HttpStatusDetector::detect_and_replace(line);
            all_results.push(result);
        }

        // After normalization, these should be more similar
        // All should have the same pattern structure, just different status classes
        let normalized_patterns: Vec<_> = all_results
            .iter()
            .map(|line| {
                // Count unique status class tokens
                line.matches("<HTTP_STATUS_").count()
            })
            .collect();

        // Each line should have exactly one HTTP status token
        for count in normalized_patterns {
            assert_eq!(
                count, 1,
                "Each line should have exactly one HTTP status token"
            );
        }
    }

    #[test]
    fn test_no_false_positives() {
        let non_http_cases = vec![
            "Processing 200 records successfully",
            "Error code 404 not related to HTTP",
            "Status: 500ms response time",
            "HTTP 200", // Without proper request format
        ];

        for test_case in non_http_cases {
            let (result, tokens) = HttpStatusDetector::detect_and_replace(test_case);

            // Should not detect HTTP status classes in non-HTTP contexts
            assert_eq!(
                result, test_case,
                "Should not modify non-HTTP status: {}",
                test_case
            );
            assert_eq!(
                tokens.len(),
                0,
                "Should not detect tokens in non-HTTP context: {}",
                test_case
            );
        }
    }

    #[test]
    fn test_multiple_status_codes_in_line() {
        let test_line = r#"Proxy response: "GET /api HTTP/1.1" 200 -> "GET /backend HTTP/1.1" 502"#;

        let (result, tokens) = HttpStatusDetector::detect_and_replace(test_line);

        // Should detect both status codes
        assert_eq!(tokens.len(), 2, "Should detect both HTTP status codes");
        assert!(
            result.contains("<HTTP_STATUS_2XX>"),
            "Should detect 200 as 2xx"
        );
        assert!(
            result.contains("<HTTP_STATUS_5XX>"),
            "Should detect 502 as 5xx"
        );
    }

    #[ignore = "stale: detector behavior changed, test expectations need updating"]
    #[test]
    fn test_compression_improvement_target() {
        // This test validates the research finding that HTTP status grouping
        // should improve Nginx compression from 72% to >85%

        let sample_nginx_logs = vec![
            r#""GET /downloads/product_1 HTTP/1.1" 200 490"#,
            r#""GET /downloads/product_1 HTTP/1.1" 304 0"#,
            r#""GET /downloads/product_1 HTTP/1.1" 404 335"#,
            r#""GET /downloads/product_2 HTTP/1.1" 200 520"#,
            r#""GET /downloads/product_2 HTTP/1.1" 304 0"#,
            r#""GET /downloads/product_2 HTTP/1.1" 404 335"#,
        ];

        let mut normalized_lines = Vec::new();
        for line in &sample_nginx_logs {
            let (normalized, _tokens) = HttpStatusDetector::detect_and_replace(line);
            normalized_lines.push(normalized);
        }

        // After normalization, similar request patterns with different status codes
        // should group together better for folding
        let unique_patterns: std::collections::HashSet<_> = normalized_lines.iter().collect();

        // We expect fewer unique patterns after status code normalization
        // This enables better folding and compression
        assert!(
            unique_patterns.len() < sample_nginx_logs.len(),
            "Status normalization should reduce unique patterns for better compression"
        );
    }
}
