// Comprehensive IPv6 ReDoS Protection Test Suite
//
// Tests that all evil IPv6 patterns scale linearly with input size.
// A vulnerable regex would show quadratic/exponential scaling.
// Uses scaling-ratio approach: immune to CPU contention.

use lessence::patterns::network::NetworkDetector;
use std::time::Instant;

fn measure_detect(input: &str, iters: u32) -> std::time::Duration {
    for _ in 0..iters / 10 {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    }
    let start = Instant::now();
    for _ in 0..iters {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    }
    start.elapsed()
}

fn assert_linear(label: &str, make_input: impl Fn(usize) -> String) {
    let small = make_input(1);
    let large = make_input(4);
    // High iteration count so each measurement spans >1ms even in release
    // mode (where operations take ~2µs). This makes scheduler noise a
    // negligible fraction of the total measurement.
    let iters = 5000;

    let time_small = measure_detect(&small, iters);
    let time_large = measure_detect(&large, iters);

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;

    assert!(
        ratio < 8.0,
        "{label}: ratio {ratio:.1}x for 4x input (expected <8.0). \
         small={s}ns, large={l}ns",
        s = time_small.as_nanos() / u128::from(iters),
        l = time_large.as_nanos() / u128::from(iters),
    );
}

// --- Evil patterns: scaling tests ---

#[test]
fn test_evil_excessive_hex_repetition_scales_linearly() {
    assert_linear("excessive_hex", |m| {
        (0..15 * m)
            .map(|i| format!("{:x}", i % 16))
            .collect::<Vec<_>>()
            .join(":")
    });
}

#[test]
fn test_evil_nested_groups_scales_linearly() {
    assert_linear("nested_groups", |m| {
        "a:b:c:d:e:f:"
            .repeat(3 * m)
            .trim_end_matches(':')
            .to_string()
    });
}

#[test]
fn test_evil_very_long_malformed_scales_linearly() {
    assert_linear("long_malformed", |m| {
        "0000:".repeat(5 * m).trim_end_matches(':').to_string()
    });
}

#[test]
fn test_evil_repeated_colons_scales_linearly() {
    assert_linear("repeated_colons", |m| ":".repeat(25 * m));
}

#[test]
fn test_evil_invalid_chars_injection_scales_linearly() {
    assert_linear("invalid_chars", |m| {
        format!(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334{}",
            "!".repeat(15 * m)
        )
    });
}

#[test]
fn test_evil_mixed_valid_invalid_scales_linearly() {
    assert_linear("mixed_chars", |m| {
        format!(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334{}",
            "@#$%^&*()".repeat(2 * m)
        )
    });
}

#[test]
fn test_evil_ipv4_like_with_colons_scales_linearly() {
    assert_linear("ipv4_colons", |m| {
        "192.168.1.1:"
            .repeat(4 * m)
            .trim_end_matches(':')
            .to_string()
    });
}

// --- Correctness: these don't need timing ---

#[test]
fn test_evil_short_but_malformed() {
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace("a:b", true, false, false);
    // Just verifying it doesn't panic
}

#[test]
fn test_evil_alphabetic_only() {
    let evil = "ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz";
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace(evil, true, false, false);
}

#[test]
fn test_evil_hex_with_special_chars() {
    let evil = "2001:0db8:85a3:0000:0000:8a2e:0370:7334<>:\"{}|\\?/";
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace(evil, true, false, false);
}

#[test]
fn test_evil_patterns_in_realistic_log_context() {
    let log_lines = vec![
        "Connection from 1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f failed",
        "Error: Malformed IPv6 a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f detected",
        "Attack attempt: :::::::::::::::::::::::::::::::::::::::::::::::::::: detected",
        "Malformed packet: 2001:0db8:85a3:0000:0000:8a2e:0370:7334!!!!!!!!!!!!!!!!!!!!!",
    ];

    for line in log_lines {
        let (_normalized, _tokens) = NetworkDetector::detect_and_replace(line, true, false, false);
        // No timing assertion — just verify no panic. Scaling tests above
        // cover the algorithmic complexity; these cover realistic contexts.
    }
}

#[test]
fn test_boundary_conditions() {
    let long_invalid = "a".repeat(100);
    let too_long = "1".repeat(101);
    let test_cases: Vec<(&str, bool, &str)> = vec![
        ("::", true, "minimum valid"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", true, "full ipv6"),
        (&long_invalid, false, "100 chars no colons"),
        (&too_long, false, "exceeds max length"),
    ];

    for (input, should_have_tokens, description) in test_cases {
        let (_normalized, tokens) = NetworkDetector::detect_and_replace(input, true, false, false);
        if should_have_tokens {
            assert!(!tokens.is_empty(), "Should detect IPv6 for: {description}");
        }
    }
}

#[test]
fn test_pre_filter_rejects_obviously_malformed() {
    let malformed = vec![
        (
            "::::::::::::::::::::::::::::::::::::::::",
            "repeated_colons",
        ),
        (":", "just_colon"),
        ("ghijklmnop:ghijklmnop:ghijklmnop", "non_hex"),
        ("2001:0db8:85a3::7334@#$%^&*()", "mixed_invalid"),
    ];

    for (sample, description) in &malformed {
        let check = NetworkDetector::is_plausible_ipv6(sample);
        assert!(
            !check.is_plausible,
            "Pre-filter should reject '{description}'"
        );
    }
}

#[test]
fn test_pre_filter_passes_structurally_valid() {
    let valid = vec![
        ("2001:0db8:85a3::8a2e:370:7334", "standard"),
        ("::1", "localhost"),
        ("fe80::1", "link_local"),
    ];

    for (sample, description) in &valid {
        let check = NetworkDetector::is_plausible_ipv6(sample);
        assert!(check.is_plausible, "Pre-filter should pass '{description}'");
    }
}
