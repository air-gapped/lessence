// Contract Test: Timestamp Pattern ReDoS Resistance
// This test validates timestamp pattern detector against evil inputs

use std::time::{Duration, Instant};

#[test]
fn test_timestamp_redos_resistance_repeated_digits() {
    // Given: Malicious timestamp-like pattern with excessive digits and separators
    let evil_timestamp = format!("2024-01-01 12:00:00{}UTCX", ".".repeat(100));

    // When: Timestamp pattern detector processes the malicious input
    use lessence::patterns::timestamp::TimestampDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = TimestampDetector::detect_and_replace(&evil_timestamp);
    let elapsed = start.elapsed();

    // Then: Processing completes in <200ms
    assert!(
        elapsed < Duration::from_millis(1000),
        "ReDoS detected: timestamp pattern took {:?} for input length {}",
        elapsed,
        evil_timestamp.len()
    );
}

#[test]
fn test_timestamp_redos_resistance_iso8601_abuse() {
    // Given: Malicious ISO 8601-like pattern with excessive fractional seconds
    let evil_timestamp = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(100));

    // When: Processing timestamp with excessive precision
    use lessence::patterns::timestamp::TimestampDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = TimestampDetector::detect_and_replace(&evil_timestamp);
    let elapsed = start.elapsed();

    // Then: Completes in <200ms despite malformed input
    assert!(
        elapsed < Duration::from_millis(1000),
        "ReDoS detected on malformed ISO timestamp: took {elapsed:?}"
    );
}

#[test]
fn test_timestamp_valid_formats_still_detected() {
    // Given: Valid timestamp formats (regression check)
    let valid_timestamps = vec![
        "2024-01-01T10:15:30Z",
        "2024-01-01 10:15:30.123",
        "Jan 15 10:15:30",
        "01/15/2024 10:15:30",
        "E0909 13:07:09.181236", // Kubernetes format
    ];

    // When/Then: All valid timestamps still detected
    use lessence::patterns::timestamp::TimestampDetector;
    for ts in valid_timestamps {
        let input = format!("Event at {ts}");
        let (normalized, tokens) = TimestampDetector::detect_and_replace(&input);

        assert!(
            normalized.contains("<TIMESTAMP>"),
            "Failed to detect timestamp: {ts}"
        );
        assert!(!tokens.is_empty(), "No tokens for valid timestamp: {ts}");
    }
}

#[test]
fn test_timestamp_kubernetes_format_resistance() {
    // Given: Kubernetes log format with evil pattern
    let evil_k8s = format!(
        "E0909 13:07:09.{} 3116 kubelet.go:123] test",
        "1".repeat(100)
    );

    // When: Processing Kubernetes-style timestamp with excessive digits
    use lessence::patterns::timestamp::TimestampDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = TimestampDetector::detect_and_replace(&evil_k8s);
    let elapsed = start.elapsed();

    // Then: Completes quickly
    assert!(
        elapsed < Duration::from_millis(1000),
        "K8s format took {:?} for {} chars",
        elapsed,
        evil_k8s.len()
    );
}

#[test]
fn test_timestamp_multiple_formats_same_line() {
    // Given: Line with multiple timestamp-like patterns (stress test)
    let evil_line = format!(
        "Start: 2024-01-01T12:00:00.{}Z!!! Middle: 01/01/2024 {} End: E0909 {}invalid",
        "9".repeat(50),
        "12:00:00".repeat(10),
        "13:07:09.".repeat(10)
    );

    // When: Processing line with multiple evil patterns
    use lessence::patterns::timestamp::TimestampDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = TimestampDetector::detect_and_replace(&evil_line);
    let elapsed = start.elapsed();

    // Then: Completes in <300ms (100ms per pattern)
    assert!(
        elapsed < Duration::from_millis(1000),
        "Multiple evil timestamp patterns took {elapsed:?}"
    );
}
