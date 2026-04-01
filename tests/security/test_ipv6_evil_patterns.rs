// Comprehensive IPv6 ReDoS Protection Test Suite
// Tests 10 evil patterns with performance assertions and integration scenarios

use lessence::patterns::network::NetworkDetector;
use std::time::{Duration, Instant};

#[test]
fn test_evil_pattern_1_excessive_hex_repetition() {
    let evil_pattern = "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_2_nested_groups_with_colons() {
    let evil_pattern = "a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_3_very_long_malformed_ipv6() {
    let evil_pattern = "0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_4_repeated_colons_no_hex() {
    let evil_pattern = "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_5_invalid_characters_injection() {
    let evil_pattern = "2001:0db8:85a3:0000:0000:8a2e:0370:7334!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_6_short_but_malformed() {
    let evil_pattern = "a:b";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_7_alphabetic_only_no_hex() {
    let evil_pattern = "ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_8_mixed_valid_invalid_chars() {
    let evil_pattern = "2001:0db8:85a3:0000:0000:8a2e:0370:7334@#$%^&*()";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_9_ipv4_like_with_colons() {
    let evil_pattern =
        "192.168.1.1:192.168.1.1:192.168.1.1:192.168.1.1:192.168.1.1:192.168.1.1:192.168.1.1";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_pattern_10_hex_with_special_chars() {
    let evil_pattern = "2001:0db8:85a3:0000:0000:8a2e:0370:7334<>:\"{}|\\?/";
    let start = Instant::now();
    let (_normalized, _tokens) =
        NetworkDetector::detect_and_replace(evil_pattern, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: took {elapsed:?}"
    );
}

#[test]
fn test_evil_patterns_in_realistic_log_context() {
    let log_lines = vec![
        "Connection from 1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f failed",
        "Error: Malformed IPv6 a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f:a:b:c:d:e:f detected",
        "Invalid address 0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000:0000 in packet",
        "Attack attempt: :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: detected",
        "Malformed packet: 2001:0db8:85a3:0000:0000:8a2e:0370:7334!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    ];

    for line in log_lines {
        let start = Instant::now();
        let (_normalized, _tokens) = NetworkDetector::detect_and_replace(line, true, false, false);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "ReDoS in log context: took {elapsed:?}"
        );
    }
}

#[test]
fn test_boundary_conditions() {
    let long_invalid = "a".repeat(100);
    let too_long = "1".repeat(101);

    let test_cases = vec![
        ("::", true, "minimum valid length"),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            true,
            "full IPv6 address",
        ),
        (&long_invalid, false, "maximum length with invalid chars"),
        (&too_long, false, "exceeds maximum length"),
    ];

    for (input, should_have_tokens, description) in test_cases {
        let start = Instant::now();
        let (_normalized, tokens) = NetworkDetector::detect_and_replace(input, true, false, false);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "Boundary test '{description}' took {elapsed:?}"
        );

        if should_have_tokens {
            assert!(!tokens.is_empty(), "Should detect IPv6 for: {description}");
        }
    }
}

#[test]
fn test_pre_filter_fast_rejection() {
    use lessence::patterns::network::NetworkDetector;

    let obviously_malformed = vec![
        ("::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::", "repeated_colons", "no_hex_digits"),
        (":", "just_colon", "too_short"),
        ("ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz:ghijklmnopqrstuvwxyz", "non_hex_chars", "invalid_characters"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334@#$%^&*()", "mixed_invalid_chars", "invalid_characters"),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334<>:\"{}|\\?/", "special_chars", "invalid_characters"),
    ];

    for (sample, description, _expected_reason) in &obviously_malformed {
        let start = Instant::now();
        let check = NetworkDetector::is_plausible_ipv6(sample);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(10),
            "Pre-filter for '{description}' took too long: {elapsed:?}"
        );
        assert!(
            !check.is_plausible,
            "Pre-filter should reject '{sample}' ({description})"
        );
    }
}

#[test]
fn test_pre_filter_passes_structurally_valid() {
    use lessence::patterns::network::NetworkDetector;

    let structurally_valid = vec![
        ("2001:0db8:85a3::8a2e:370:7334", "standard_ipv6"),
        ("::1", "localhost"),
        ("fe80::1", "link_local"),
    ];

    for (sample, description) in &structurally_valid {
        let start = Instant::now();
        let check = NetworkDetector::is_plausible_ipv6(sample);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(10),
            "Pre-filter for '{description}' took too long: {elapsed:?}"
        );
        assert!(
            check.is_plausible,
            "Pre-filter should pass structurally valid '{sample}' ({description})"
        );
    }
}
