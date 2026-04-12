// Integration Test: Normalization Module Compatibility
// Tests integration with existing normalization workflow

use lessence::patterns::timestamp::UnifiedTimestampDetector;

#[test]
fn test_detect_and_replace_api_compatibility() {
    // Verify that the existing API is preserved
    let input = "2025-09-29T10:15:30Z Processing request";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    // API contract verification
    assert_eq!(result, "<TIMESTAMP> Processing request");
    assert_eq!(tokens.len(), 1);

    // Verify token format matches existing expectations
    match &tokens[0] {
        lessence::patterns::Token::Timestamp(ts) => {
            assert_eq!(ts, "2025-09-29T10:15:30Z");
        }
        _ => panic!("Expected Timestamp token"),
    }
}

#[test]
fn test_multiple_timestamp_handling() {
    let input = "Start: 2025-09-29T10:15:30Z End: 2025-09-29T10:16:45Z";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(result, "Start: <TIMESTAMP> End: <TIMESTAMP>");
    assert_eq!(tokens.len(), 2);

    // Verify both timestamps are captured
    if let lessence::patterns::Token::Timestamp(ts1) = &tokens[0] {
        assert_eq!(ts1, "2025-09-29T10:15:30Z");
    } else {
        panic!("Expected first Timestamp token");
    }

    if let lessence::patterns::Token::Timestamp(ts2) = &tokens[1] {
        assert_eq!(ts2, "2025-09-29T10:16:45Z");
    } else {
        panic!("Expected second Timestamp token");
    }
}

#[test]
fn test_no_timestamp_handling() {
    let input = "Processing request without timestamp";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(result, input);
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_pattern_accuracy_preservation() {
    // Test that all major timestamp formats are still detected correctly
    let test_cases = vec![
        ("2025-09-29T10:15:30.123Z", "<TIMESTAMP>"),
        ("E0929 13:07:09.181236 3116 error", "<TIMESTAMP> 3116 error"),
        ("Jan 29 10:15:30 kernel", "<TIMESTAMP> kernel"),
        ("[29/Sep/2025:10:15:30 +0000]", "<TIMESTAMP>"),
        ("2025-09-29 10:15:30,123", "<TIMESTAMP>"),
    ];

    for (input, expected) in test_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(result, expected, "Failed for input: {}", input);
        assert!(!tokens.is_empty(), "No tokens found for input: {}", input);
    }
}

#[test]
fn test_token_format_consistency() {
    let input = "Multiple formats: 2025-09-29T10:15:30Z and Jan 29 10:15:30";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(result, "Multiple formats: <TIMESTAMP> and <TIMESTAMP>");
    assert_eq!(tokens.len(), 2);

    // All tokens should be Timestamp variants
    for token in tokens {
        assert!(matches!(token, lessence::patterns::Token::Timestamp(_)));
    }
}

#[test]
fn test_performance_scales_linearly() {
    use std::time::Instant;

    let small = "2025-09-29T10:15:30Z ".repeat(250);
    let large = "2025-09-29T10:15:30Z ".repeat(1000);
    let iters = 10;

    // Warmup
    for _ in 0..3 {
        let _ = UnifiedTimestampDetector::detect_and_replace(&small);
    }

    let start = Instant::now();
    for _ in 0..iters {
        let _ = UnifiedTimestampDetector::detect_and_replace(&small);
    }
    let time_small = start.elapsed();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = UnifiedTimestampDetector::detect_and_replace(&large);
    }
    let time_large = start.elapsed();

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;
    assert!(
        ratio < 8.0,
        "1000-timestamp detection should scale linearly: 4x input took {ratio:.1}x"
    );

    // Also verify correctness
    let (_result, tokens) = UnifiedTimestampDetector::detect_and_replace(&large);
    assert_eq!(tokens.len(), 1000);
}

#[test]
fn test_edge_case_handling() {
    // Test edge cases that might break the normalization flow
    let edge_cases = vec![
        "",  // Empty string
        "No timestamps here at all",  // No matches
        "2025-13-45T25:99:99Z",  // Invalid but pattern-matching timestamp
        "Almost 2025-09-29T10:15 timestamp",  // Partial match
        "Nested [2025-09-29T10:15:30Z] timestamps",  // Bracketed
    ];

    for input in edge_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        // Should not panic or crash
        assert!(result.len() >= 0);  // Basic sanity check
        assert!(tokens.len() >= 0);  // Basic sanity check
    }
}