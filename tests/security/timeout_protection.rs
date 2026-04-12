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

#[test]
fn test_email_timeout_scales_linearly() {
    let small = format!("{}@{}.com!!!", "a".repeat(25), "b".repeat(25));
    let large = format!("{}@{}.com!!!", "a".repeat(100), "b".repeat(100));

    crate::common::assert_linear_scaling("email_evil", &small, &large, |input| {
        let detector = EmailPatternDetector::new().unwrap();
        let _ = detector.detect_and_replace(input);
    });
}

#[test]
fn test_ipv6_timeout_scales_linearly() {
    let small = (0..8)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join(":")
        + "::invalid";
    let large = (0..32)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join(":")
        + "::invalid";

    crate::common::assert_linear_scaling("ipv6_evil", &small, &large, |input| {
        let _ = NetworkDetector::detect_and_replace(input, true, true, true);
    });
}

#[test]
fn test_timestamp_timeout_scales_linearly() {
    let small = format!("2024-01-01T12:00:00.{}UTCX", "0".repeat(25));
    let large = format!("2024-01-01T12:00:00.{}UTCX", "0".repeat(100));

    crate::common::assert_linear_scaling("timestamp_evil", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_combined_patterns_scales_linearly() {
    let small = format!(
        "2024-01-01T12:00:00.{}UTCX User {}@{}.com!!! from {}::invalid logged in",
        "0".repeat(12),
        "a".repeat(12),
        "b".repeat(12),
        (0..4)
            .map(|i| format!("{:x}", i % 16))
            .collect::<Vec<_>>()
            .join(":")
    );
    let large = format!(
        "2024-01-01T12:00:00.{}UTCX User {}@{}.com!!! from {}::invalid logged in",
        "0".repeat(48),
        "a".repeat(48),
        "b".repeat(48),
        (0..16)
            .map(|i| format!("{:x}", i % 16))
            .collect::<Vec<_>>()
            .join(":")
    );

    crate::common::assert_linear_scaling("combined_evil", &small, &large, |input| {
        let config = Config::default();
        let normalizer = Normalizer::new(config);
        let _ = normalizer.normalize_line(input.to_string());
    });
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
