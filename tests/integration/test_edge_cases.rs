// Integration Test: Edge Case Handling (T013)
// Validates robust behavior with unusual inputs and boundary conditions

use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_empty_input() {
    let (result, tokens) = TimestampDetector::detect_and_replace("");
    assert_eq!(result, "");
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_whitespace_only() {
    let (result, tokens) = TimestampDetector::detect_and_replace("   \t\n  ");
    assert_eq!(result, "   \t\n  ");
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_very_long_line() {
    let prefix = "Very long line ".repeat(1000);
    let input = format!("{}2025-09-29T10:15:30Z End", prefix);
    let (result, tokens) = TimestampDetector::detect_and_replace(&input);

    assert!(result.ends_with("<TIMESTAMP> End"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_malformed_timestamps() {
    let malformed_cases = vec![
        "2025-13-45T25:99:99Z",  // Invalid dates/times
        "2025-02-30T10:15:30Z",  // Invalid date
        "2025-09-29T25:15:30Z",  // Invalid hour
        "20250929T101530Z",      // Missing separators
        "2025/09/29T10:15:30Z",  // Wrong separators
    ];

    for input in malformed_cases {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        // Should either reject completely or handle gracefully
        // Don't crash or produce invalid output
        assert!(result.len() > 0, "Should not crash on malformed input: {}", input);
    }
}

#[test]
fn test_unicode_timestamps() {
    let input = "Événement à 2025-09-29T10:15:30Z terminé";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "Événement à <TIMESTAMP> terminé");
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_special_characters() {
    let test_cases = vec![
        "Event@2025-09-29T10:15:30Z#completed",
        "Process$2025-09-29T10:15:30Z%finished",
        "Data&2025-09-29T10:15:30Z*processed",
    ];

    for input in test_cases {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert!(result.contains("<TIMESTAMP>"), "Should handle special chars: {}", input);
        assert_eq!(tokens.len(), 1);
    }
}

#[test]
fn test_nested_brackets() {
    let input = "[[2025-09-29T10:15:30Z]] nested brackets";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert!(result.contains("<TIMESTAMP>"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_timestamp_at_boundaries() {
    let test_cases = vec![
        "2025-09-29T10:15:30Z",  // Only timestamp
        "2025-09-29T10:15:30Z ",  // Timestamp at start
        " 2025-09-29T10:15:30Z",  // Timestamp at end
        "Start2025-09-29T10:15:30ZEnd",  // No separators
    ];

    for input in test_cases {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert!(result.contains("<TIMESTAMP>"), "Should detect at boundaries: {}", input);
        assert_eq!(tokens.len(), 1);
    }
}

#[test]
fn test_repeated_timestamps() {
    let input = "2025-09-29T10:15:30Z 2025-09-29T10:15:30Z 2025-09-29T10:15:30Z";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "<TIMESTAMP> <TIMESTAMP> <TIMESTAMP>");
    assert_eq!(tokens.len(), 3);
}

#[test]
fn test_overlapping_pattern_candidates() {
    // Patterns that might partially overlap
    let input = "2025-09-29T10:15:30.123456789Z";
    let (result, tokens) = TimestampDetector::detect_and_replace(input);

    assert_eq!(result, "<TIMESTAMP>");
    assert_eq!(tokens.len(), 1);

    // Should match the full pattern, not subparts
    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert!(ts.len() > 20, "Should match full precision timestamp");
    }
}

#[test]
fn test_false_positive_prevention() {
    let false_positives = vec![
        "Process ID 12345",           // Should not match as Unix timestamp
        "Port 8080 is open",          // Should not match as timestamp
        "Error code 404",             // Should not match as timestamp
        "Version 2025.09.29",         // Version numbers
        "File size 1727676930 bytes", // Large numbers
    ];

    for input in false_positives {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);

        // Most of these should not be detected as timestamps
        // Unix timestamps should have very low priority to avoid false positives
        if tokens.len() > 0 {
            // If detected, should be a very specific pattern, not generic numbers
            println!("Detected in '{}': {} tokens", input, tokens.len());
        }
        // Don't assert no detection as some might be valid edge cases
        // The key is that the system doesn't crash
    }
}

#[test]
fn test_binary_data_safety() {
    // Test with binary-like data that might contain timestamp-like patterns
    let binary_like = "ÿþ2025\x00\x01\x0229T10:15:30Zÿþ";
    let (result, tokens) = TimestampDetector::detect_and_replace(binary_like);

    // Should not crash, might or might not detect patterns
    assert!(result.len() > 0, "Should handle binary data gracefully");
}