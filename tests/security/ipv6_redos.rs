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

#[test]
fn test_ipv6_redos_repeated_groups_scales_linearly() {
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

    crate::common::assert_linear_scaling("repeated_groups", &small, &large, |input| {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    });
}

#[test]
fn test_ipv6_redos_double_colon_abuse_scales_linearly() {
    let small = (0..5)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join("::")
        + "::invalid";
    let large = (0..20)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join("::")
        + "::invalid";

    crate::common::assert_linear_scaling("double_colon_abuse", &small, &large, |input| {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    });
}

#[test]
fn test_ipv6_redos_long_pattern_scales_linearly() {
    let small = "a]b:".repeat(12).clone() + "::invalid";
    let large = "a]b:".repeat(48).clone() + "::invalid";

    crate::common::assert_linear_scaling("long_pattern", &small, &large, |input| {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
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
