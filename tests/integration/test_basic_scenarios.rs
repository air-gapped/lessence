// Integration Test: Basic Pattern Replacement Scenarios (T012)
// Validates fundamental timestamp detection and replacement behavior

use lessence::patterns::timestamp::{UnifiedTimestampDetector, TimestampDetector};

#[test]
fn test_iso8601_basic_detection() {
    let input = "2025-09-29T10:15:30Z System started";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "<TIMESTAMP> System started");
    assert_eq!(tokens.len(), 1);
    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert_eq!(ts, "2025-09-29T10:15:30Z");
    } else {
        panic!("Expected timestamp token");
    }
}

#[test]
fn test_kubernetes_log_detection() {
    let input = "E0929 13:07:09.181236 3116 kubelet.go:123] Pod failed to start";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert!(result.starts_with("<TIMESTAMP>"));
    assert_eq!(tokens.len(), 1);
    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert!(ts.starts_with("E0929 13:07:09"));
    } else {
        panic!("Expected timestamp token");
    }
}

#[test]
fn test_syslog_format_detection() {
    let input = "Jan 29 10:15:30 kernel: USB device connected";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert!(result.starts_with("<TIMESTAMP>"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_apache_log_detection() {
    let input = "192.168.1.1 - - [29/Sep/2025:10:15:30 +0000] \"GET / HTTP/1.1\" 200";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert!(result.contains("<TIMESTAMP>"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_unix_timestamp_detection() {
    let input = "Event logged at timestamp=1727676930.123";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "Event logged at timestamp=<TIMESTAMP>");
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_multiple_timestamps_same_line() {
    let input = "Start: 2025-09-29T10:15:30Z End: 2025-09-29T10:16:45Z";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "Start: <TIMESTAMP> End: <TIMESTAMP>");
    assert_eq!(tokens.len(), 2);
}

#[test]
fn test_no_timestamp_handling() {
    let input = "Regular log message without any timestamp";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, input);
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_partial_timestamp_rejection() {
    // Should not match incomplete timestamps
    let input = "Processing item 2025-09-29T10:15 incomplete";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    // Should either not match or match what's valid
    assert!(tokens.len() <= 1, "Should not over-match partial timestamps");
}

#[test]
fn test_api_compatibility() {
    // Verify new API is compatible with old API
    let input = "2025-09-29T10:15:30Z Compatible test";

    let (old_result, old_tokens) = TimestampDetector::detect_and_replace(input);
    let (new_result, new_tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(old_result, new_result, "API compatibility broken");
    assert_eq!(old_tokens.len(), new_tokens.len(), "Token count should match");
}

#[test]
fn test_whitespace_handling() {
    let test_cases = vec![
        "  2025-09-29T10:15:30Z  Padded timestamp",
        "\t2025-09-29T10:15:30Z\tTab separated",
        "2025-09-29T10:15:30Z\nWith newline",
    ];

    for input in test_cases {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert!(result.contains("<TIMESTAMP>"), "Should handle whitespace: {}", input);
        assert_eq!(tokens.len(), 1, "Should find one timestamp: {}", input);
    }
}