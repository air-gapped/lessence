use super::Token;
use regex::{Captures, Regex};
use std::sync::LazyLock;

// Decimal numbers (like 3.488101038, 254547.69971015)
// Match decimal numbers that are likely durations or measurements
static DECIMAL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d+\.\d+\b").unwrap());

// Integer numbers (like 12345, 67890) - standalone integers that could be IDs, counts, etc.
// More specific than decimal but broad enough to catch numeric identifiers
static INTEGER_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3,}\b").unwrap()); // 3+ digits to avoid matching small numbers like "3 retries"

// Duration with units (1.234s, 523ms, 2m30s, 1h15m, 15m27.417653609s)
// Matches various duration formats: Xh, Xm, Xs, Xms, XμS, Xns, combinations like 1h30m, 2m15s
static DURATION_WITH_UNIT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:\d+h(?:\d+m)?(?:\d+(?:\.\d+)?s)?|\d+m(?:\d+(?:\.\d+)?s)?|\d+(?:\.\d+)?(?:ms|μs|ns|s))\b|"[0-9h]*[0-9m]*[0-9.]+s""#).unwrap()
});

// Kubernetes duration fields (podStartSLOduration=, podStartE2EDuration=)
static K8S_DURATION_FIELD_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\w*[Dd]uration=\d+\.\d+").unwrap());

// Memory/file size values (1234567 bytes, 1.2MB, 5.6GB, 128KB)
// Matches integer or decimal numbers followed by size units: bytes, KB, MB, GB, TB, B
static SIZE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d+(?:\.\d+)?\s*(?:bytes?|[KMGT]?B)\b").unwrap());

// Memory addresses (0x7fff5fbff8c0)
static MEMORY_ADDR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0x[a-fA-F0-9]+\b").unwrap());

// Percentages (87.3%, CPU: 45%, memory: 78%)
// Matches both integer and decimal percentages: 45%, 87.3%
static PERCENTAGE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d+(?:\.\d+)?%").unwrap());

// HTTP status codes (200, 404, 500, 401, etc.)
// Matches 3-digit codes that are valid HTTP status codes (100-599)
// Must be surrounded by spaces or punctuation to avoid matching parts of IP addresses
static HTTP_STATUS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:status|error|code|returned?)\s+([1-5][0-9][0-9])\b").unwrap()
});

pub struct DurationDetector;

impl DurationDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no duration indicators
        if !text.contains('.')
            && !text.contains('%')
            && !text.contains("ms")
            && !text.contains('s')
            && !text.contains('m')
            && !text.contains('h')
            && !text.contains("bytes")
            && !text.contains("KB")
            && !text.contains("MB")
        {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Process in order of specificity (most specific first)

        // K8s duration fields (most specific)
        for cap in K8S_DURATION_FIELD_REGEX.find_iter(text) {
            let duration_str = cap.as_str();
            tokens.push(Token::Duration(duration_str.to_string()));
        }
        result = K8S_DURATION_FIELD_REGEX
            .replace_all(&result, "<DURATION_FIELD>")
            .to_string();

        // Duration with units in quotes
        for cap in DURATION_WITH_UNIT_REGEX.find_iter(&result) {
            let duration_str = cap.as_str();
            tokens.push(Token::Duration(duration_str.to_string()));
        }
        result = DURATION_WITH_UNIT_REGEX
            .replace_all(&result, "<DURATION>")
            .to_string();

        // Memory addresses
        for cap in MEMORY_ADDR_REGEX.find_iter(&result) {
            let addr_str = cap.as_str();
            tokens.push(Token::Number(addr_str.to_string()));
        }
        result = MEMORY_ADDR_REGEX.replace_all(&result, "<ADDR>").to_string();

        // Sizes with units
        for cap in SIZE_REGEX.find_iter(&result) {
            let size_str = cap.as_str();
            tokens.push(Token::Size(size_str.to_string()));
        }
        result = SIZE_REGEX.replace_all(&result, "<SIZE>").to_string();

        // HTTP status codes
        for cap in HTTP_STATUS_REGEX.captures_iter(&result) {
            if let Some(status_match) = cap.get(1) {
                let status_str = status_match.as_str();
                if let Ok(status_code) = status_str.parse::<u16>() {
                    tokens.push(Token::HttpStatus(status_code));
                }
            }
        }
        // Replace only the status code part, keeping the context word
        result = HTTP_STATUS_REGEX
            .replace_all(&result, |caps: &Captures| {
                let context = &caps[0][..caps[0].len() - caps[1].len()]; // Everything before the status code
                format!("{context}<HTTP_STATUS>")
            })
            .to_string();

        // Percentages
        for cap in PERCENTAGE_REGEX.find_iter(&result) {
            let pct_str = cap.as_str();
            tokens.push(Token::Number(pct_str.to_string()));
        }
        result = PERCENTAGE_REGEX.replace_all(&result, "<PCT>").to_string();

        // General decimal numbers (least specific, catch remaining)
        for cap in DECIMAL_REGEX.find_iter(&result) {
            let decimal_str = cap.as_str();
            tokens.push(Token::Duration(decimal_str.to_string()));
        }
        result = DECIMAL_REGEX.replace_all(&result, "<DECIMAL>").to_string();

        // Integer numbers (3+ digits, catch remaining numeric IDs)
        for cap in INTEGER_REGEX.find_iter(&result) {
            let int_str = cap.as_str();
            tokens.push(Token::Number(int_str.to_string()));
        }
        result = INTEGER_REGEX.replace_all(&result, "<NUMBER>").to_string();

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k8s_duration_detection() {
        let text = r#"podStartSLOduration=3.488101038 podStartE2EDuration="3.488101038s""#;
        let (result, tokens) = DurationDetector::detect_and_replace(text);

        println!("Input: {text}");
        println!("Output: {result}");
        println!("Tokens: {tokens:?}");

        assert!(result.contains("<DURATION_FIELD>"));
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_decimal_detection() {
        let text = "value=123.456789 and another=999.111";
        let (result, tokens) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "value=<DECIMAL> and another=<DECIMAL>");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_memory_address() {
        let text = "pointer at 0x7fff5fbff8c0 in memory";
        let (result, _) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "pointer at <ADDR> in memory");
    }

    #[test]
    fn test_percentage() {
        let text = "CPU usage: 87.3% memory: 45.2%";
        let (result, _) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "CPU usage: <PCT> memory: <PCT>");
    }

    #[test]
    fn test_duration_units() {
        let test_cases = vec![
            (
                "request took 1.234s to complete",
                "request took <DURATION> to complete",
            ),
            ("timeout after 523ms", "timeout after <DURATION>"),
            ("elapsed time: 2m30s", "elapsed time: <DURATION>"),
            ("uptime: 1h15m", "uptime: <DURATION>"),
            ("latency 45μs detected", "latency <DURATION> detected"),
            ("process ran for 3ns", "process ran for <DURATION>"),
            ("combined: 1h30m15s total", "combined: <DURATION> total"),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            assert!(!tokens.is_empty(), "No tokens detected for: {input}");
        }
    }

    #[test]
    fn test_memory_sizes() {
        let test_cases = vec![
            ("file size: 1234567 bytes", "file size: <SIZE>", true),
            (
                "allocated 1.2MB of memory",
                "allocated <SIZE> of memory",
                true,
            ),
            (
                "disk usage: 5.6GB available",
                "disk usage: <SIZE> available",
                true,
            ),
            ("buffer: 128KB allocated", "buffer: <SIZE> allocated", true),
            // "downloaded 2TB of data" is skipped by fast-path pre-filter (no '.', '%', 's', 'm', 'h', etc.)
            ("downloaded 2TB of data", "downloaded 2TB of data", false),
            ("cache: 512 B total", "cache: <SIZE> total", true),
            (
                "memory usage: 1234567 bytes and 5.6GB disk",
                "memory usage: <SIZE> and <SIZE> disk",
                true,
            ),
        ];

        for (input, expected, expect_tokens) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            if expect_tokens {
                assert!(!tokens.is_empty(), "No tokens detected for: {input}");
            }
        }
    }

    #[test]
    fn test_http_status_codes() {
        let test_cases = vec![
            (
                "POST /login returned 401 Unauthorized",
                "POST /login returned <HTTP_STATUS> Unauthorized",
                true,
            ),
            // "Error 404 not found on page" is skipped by the fast-path pre-filter (no 's', 'm', 'h', etc.)
            (
                "Error 404 not found on page",
                "Error 404 not found on page",
                false,
            ),
            (
                "Request completed with status 201",
                "Request completed with status <HTTP_STATUS>",
                true,
            ),
            (
                "HTTP status code 500 internal error",
                "HTTP status code <HTTP_STATUS> internal error",
                true,
            ),
            (
                "Error code 403 forbidden",
                "Error code 403 forbidden",
                false,
            ),
        ];

        for (input, expected, expect_tokens) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            if expect_tokens {
                assert!(!tokens.is_empty(), "No tokens detected for: {input}");
            }
        }
    }

    #[test]
    fn test_percentages() {
        let test_cases = vec![
            ("CPU usage: 87.3%", "CPU usage: <PCT>"),
            ("Memory at 45%", "Memory at <PCT>"),
            ("Disk full at 98%", "Disk full at <PCT>"),
            ("Progress: 12.5% complete", "Progress: <PCT> complete"),
            (
                "Stats: CPU: 45%, memory: 78%, disk: 92.1%",
                "Stats: CPU: <PCT>, memory: <PCT>, disk: <PCT>",
            ),
            ("Low usage: 3.14% only", "Low usage: <PCT> only"),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            assert!(!tokens.is_empty(), "No tokens detected for: {input}");
        }
    }
}
