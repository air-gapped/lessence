// Contract Test: Pattern Detection Timeout Protection
//
// Tests that the full normalization pipeline scales linearly on evil
// inputs. Uses scaling-ratio approach instead of absolute wall-clock
// thresholds, so results are immune to CPU contention.

use lessence::config::Config;
use lessence::normalize::Normalizer;
use lessence::patterns::email::EmailPatternDetector;
use lessence::patterns::network::NetworkDetector;
use lessence::patterns::timestamp::TimestampDetector;
use std::time::Instant;

fn assert_linear_scaling<F: Fn(usize) -> String>(
    label: &str,
    make_input: F,
    measure: impl Fn(&str, u32) -> std::time::Duration,
) {
    let small = make_input(1);
    let large = make_input(4);
    let iters = 200;

    let time_small = measure(&small, iters);
    let time_large = measure(&large, iters);

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
fn test_email_timeout_scales_linearly() {
    assert_linear_scaling(
        "email_evil",
        |m| format!("{}@{}.com!!!", "a".repeat(25 * m), "b".repeat(25 * m)),
        |input, iters| {
            let detector = EmailPatternDetector::new().unwrap();
            for _ in 0..iters / 10 {
                let _ = detector.detect_and_replace(input);
            }
            let start = Instant::now();
            for _ in 0..iters {
                let _ = detector.detect_and_replace(input);
            }
            start.elapsed()
        },
    );
}

#[test]
fn test_ipv6_timeout_scales_linearly() {
    assert_linear_scaling(
        "ipv6_evil",
        |m| {
            let groups = 8 * m;
            (0..groups)
                .map(|i| format!("{:x}", i % 16))
                .collect::<Vec<_>>()
                .join(":")
                + "::invalid"
        },
        |input, iters| {
            for _ in 0..iters / 10 {
                let _ = NetworkDetector::detect_and_replace(input, true, true, true);
            }
            let start = Instant::now();
            for _ in 0..iters {
                let _ = NetworkDetector::detect_and_replace(input, true, true, true);
            }
            start.elapsed()
        },
    );
}

#[test]
fn test_timestamp_timeout_scales_linearly() {
    assert_linear_scaling(
        "timestamp_evil",
        |m| format!("2024-01-01T12:00:00.{}UTCX", "0".repeat(25 * m)),
        |input, iters| {
            for _ in 0..iters / 10 {
                let _ = TimestampDetector::detect_and_replace(input);
            }
            let start = Instant::now();
            for _ in 0..iters {
                let _ = TimestampDetector::detect_and_replace(input);
            }
            start.elapsed()
        },
    );
}

#[test]
fn test_combined_patterns_scales_linearly() {
    assert_linear_scaling(
        "combined_evil",
        |m| {
            format!(
                "2024-01-01T12:00:00.{}UTCX User {}@{}.com!!! from {}::invalid logged in",
                "0".repeat(12 * m),
                "a".repeat(12 * m),
                "b".repeat(12 * m),
                (0..4 * m)
                    .map(|i| format!("{:x}", i % 16))
                    .collect::<Vec<_>>()
                    .join(":")
            )
        },
        |input, iters| {
            let config = Config::default();
            let normalizer = Normalizer::new(config);
            for _ in 0..iters / 10 {
                let _ = normalizer.normalize_line(input.to_string());
            }
            let start = Instant::now();
            for _ in 0..iters {
                let _ = normalizer.normalize_line(input.to_string());
            }
            start.elapsed()
        },
    );
}

#[test]
fn test_evil_inputs_do_not_panic() {
    let evil_inputs = vec![
        format!("{}@{}.com!!!", "a".repeat(1000), "b".repeat(1000)),
        "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8::invalid"
            .to_string(),
        format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(500)),
    ];

    let config = Config::default();

    for input in evil_inputs {
        let normalizer = Normalizer::new(config.clone());
        let result = std::panic::catch_unwind(|| normalizer.normalize_line(input));
        assert!(result.is_ok(), "Pattern detection panicked on evil input");
    }
}
