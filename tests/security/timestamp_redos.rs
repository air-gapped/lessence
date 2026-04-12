// Contract Test: Timestamp Pattern ReDoS Resistance
//
// Tests that timestamp pattern detection scales linearly with input size.
// Uses scaling-ratio approach: 4x input should take ~4x time, not 16x.

use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_timestamp_redos_excessive_fractional_seconds_scales_linearly() {
    let small = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(25));
    let large = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(100));

    crate::common::assert_linear_scaling("fractional_seconds", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_timestamp_redos_repeated_dots_scales_linearly() {
    let small = format!("2024-01-01 12:00:00{}UTCX", ".".repeat(25));
    let large = format!("2024-01-01 12:00:00{}UTCX", ".".repeat(100));

    crate::common::assert_linear_scaling("repeated_dots", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_timestamp_redos_k8s_excessive_digits_scales_linearly() {
    let small = format!("E0909 13:07:09.{} 3116 kubelet.go:123] test", "1".repeat(25));
    let large = format!("E0909 13:07:09.{} 3116 kubelet.go:123] test", "1".repeat(100));

    crate::common::assert_linear_scaling("k8s_excessive_digits", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_timestamp_redos_multiple_formats_scales_linearly() {
    let build = |count: usize| {
        let mut line = String::new();
        for _ in 0..count {
            line.push_str("2024-01-01T12:00:00.999Z ");
            line.push_str("01/01/2024 12:00:00 ");
            line.push_str("E0909 13:07:09.123456 ");
        }
        line
    };
    let small = build(3);
    let large = build(12);

    crate::common::assert_linear_scaling("multiple_formats", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_timestamp_valid_formats_still_detected() {
    let valid_timestamps = vec![
        "2024-01-01T10:15:30Z",
        "2024-01-01 10:15:30.123",
        "Jan 15 10:15:30",
        "01/15/2024 10:15:30",
        "E0909 13:07:09.181236",
    ];

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
