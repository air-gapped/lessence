// Contract Test: Timestamp Pattern ReDoS Resistance
//
// Tests that timestamp pattern detection scales linearly with input size.
// Uses scaling-ratio approach: 4x input should take ~4x time, not 16x.

use lessence::patterns::timestamp::TimestampDetector;
use std::time::Instant;

fn measure_timestamp_detect(input: &str, iterations: u32) -> std::time::Duration {
    for _ in 0..iterations / 10 {
        let _ = TimestampDetector::detect_and_replace(input);
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = TimestampDetector::detect_and_replace(input);
    }
    start.elapsed()
}

fn assert_linear_scaling(label: &str, make_input: impl Fn(usize) -> String) {
    let small = make_input(1);
    let large = make_input(4);
    let iters = 500;

    let time_small = measure_timestamp_detect(&small, iters);
    let time_large = measure_timestamp_detect(&large, iters);

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;

    assert!(
        ratio < 8.0,
        "{label}: scaling ratio {ratio:.1}x for 4x input (expected <8.0). \
         small={small_ns}ns, large={large_ns}ns",
        small_ns = time_small.as_nanos() / u128::from(iters),
        large_ns = time_large.as_nanos() / u128::from(iters),
    );
}

#[test]
fn test_timestamp_redos_excessive_fractional_seconds_scales_linearly() {
    assert_linear_scaling("fractional_seconds", |multiplier| {
        let len = 25 * multiplier;
        format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(len))
    });
}

#[test]
fn test_timestamp_redos_repeated_dots_scales_linearly() {
    assert_linear_scaling("repeated_dots", |multiplier| {
        let len = 25 * multiplier;
        format!("2024-01-01 12:00:00{}UTCX", ".".repeat(len))
    });
}

#[test]
fn test_timestamp_redos_k8s_excessive_digits_scales_linearly() {
    assert_linear_scaling("k8s_excessive_digits", |multiplier| {
        let len = 25 * multiplier;
        format!(
            "E0909 13:07:09.{} 3116 kubelet.go:123] test",
            "1".repeat(len)
        )
    });
}

#[test]
fn test_timestamp_redos_multiple_formats_scales_linearly() {
    assert_linear_scaling("multiple_formats", |multiplier| {
        let count = 3 * multiplier;
        let mut line = String::new();
        for _ in 0..count {
            line.push_str("2024-01-01T12:00:00.999Z ");
            line.push_str("01/01/2024 12:00:00 ");
            line.push_str("E0909 13:07:09.123456 ");
        }
        line
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
