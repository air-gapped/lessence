// Contract Test: IPv6 Pattern ReDoS Resistance
//
// Tests that IPv6 pattern detection scales linearly with input size.
// A vulnerable regex would show quadratic or exponential scaling
// (ratio >> 4x for 4x input). We assert ratio < 8.0 which catches
// any super-linear behavior while tolerating normal measurement noise.
//
// This approach is immune to CPU contention from parallel test runs
// because both measurements are slowed proportionally.

use lessence::patterns::network::NetworkDetector;
use std::time::Instant;

/// Measure how long NetworkDetector takes on a given input, averaged
/// over multiple iterations to reduce noise.
fn measure_network_detect(input: &str, iterations: u32) -> std::time::Duration {
    // Warmup
    for _ in 0..iterations / 10 {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    }
    start.elapsed()
}

/// Assert that processing scales linearly: 4x input should take ~4x time,
/// not 16x (quadratic) or worse (exponential).
fn assert_linear_scaling(label: &str, make_input: impl Fn(usize) -> String) {
    let small = make_input(1);
    let large = make_input(4);
    let iters = 500;

    let time_small = measure_network_detect(&small, iters);
    let time_large = measure_network_detect(&large, iters);

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;

    // Linear: ratio ≈ 4.0. Quadratic: ratio ≈ 16.0.
    // Threshold of 8.0 gives 2x headroom for noise while catching ReDoS.
    assert!(
        ratio < 8.0,
        "{label}: scaling ratio {ratio:.1}x for 4x input (expected <8.0, \
         quadratic would be ~16.0). small={small_ns}ns, large={large_ns}ns",
        small_ns = time_small.as_nanos() / u128::from(iters),
        large_ns = time_large.as_nanos() / u128::from(iters),
    );
}

#[test]
fn test_ipv6_redos_repeated_groups_scales_linearly() {
    assert_linear_scaling("repeated_groups", |multiplier| {
        let groups = 8 * multiplier;
        (0..groups)
            .map(|i| format!("{:x}", i % 16))
            .collect::<Vec<_>>()
            .join(":")
            + "::invalid"
    });
}

#[test]
fn test_ipv6_redos_double_colon_abuse_scales_linearly() {
    assert_linear_scaling("double_colon_abuse", |multiplier| {
        let groups = 5 * multiplier;
        (0..groups)
            .map(|i| format!("{:x}", i % 16))
            .collect::<Vec<_>>()
            .join("::")
            + "::invalid"
    });
}

#[test]
fn test_ipv6_redos_long_pattern_scales_linearly() {
    assert_linear_scaling("long_pattern", |multiplier| {
        "a]b:".repeat(12 * multiplier) + "::invalid"
    });
}

#[test]
fn test_ipv6_valid_addresses_still_detected() {
    let valid_ipv6 = vec![
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::1",
        "fe80::1",
    ];

    for ipv6 in valid_ipv6 {
        let input = format!("Address: {ipv6}");
        let (normalized, tokens) = NetworkDetector::detect_and_replace(&input, true, false, false);
        assert!(normalized.contains("<IP>"), "Failed to detect IPv6: {ipv6}");
        assert!(!tokens.is_empty(), "No tokens for valid IPv6: {ipv6}");
    }
}
