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
    let input = format!("{prefix}2025-09-29T10:15:30Z End");
    let (result, tokens) = TimestampDetector::detect_and_replace(&input);

    assert!(result.ends_with("<TIMESTAMP> End"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_malformed_timestamps() {
    let malformed_cases = vec![
        "2025-13-45T25:99:99Z", // Invalid dates/times
        "2025-02-30T10:15:30Z", // Invalid date
        "2025-09-29T25:15:30Z", // Invalid hour
        "20250929T101530Z",     // Missing separators
        "2025/09/29T10:15:30Z", // Wrong separators
    ];

    // Shape-valid but semantically impossible dates ARE replaced: the
    // detector is regex-shaped, not a calendar validator, and for folding
    // purposes treating 2025-02-30 as a timestamp is correct behavior.
    for input in &malformed_cases[..3] {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert_eq!(result, "<TIMESTAMP>", "shape-valid input: {input}");
        assert_eq!(tokens.len(), 1);
    }
    // Wrong separators don't match any format — input must pass through
    // byte-identical with no tokens.
    for input in &malformed_cases[3..] {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert_eq!(&result, input, "wrong-separator input must be untouched");
        assert!(tokens.is_empty());
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
        assert!(
            result.contains("<TIMESTAMP>"),
            "Should handle special chars: {input}"
        );
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
        "2025-09-29T10:15:30Z ", // Timestamp at start
        " 2025-09-29T10:15:30Z", // Timestamp at end
    ];

    for input in test_cases {
        let (result, tokens) = TimestampDetector::detect_and_replace(input);
        assert!(
            result.contains("<TIMESTAMP>"),
            "Should detect at boundaries: {input}"
        );
        assert_eq!(tokens.len(), 1);
    }

    // No word-boundary separators: the embedded timestamp is NOT detected
    // and the input passes through unchanged.
    let no_sep = "Start2025-09-29T10:15:30ZEnd";
    let (result, tokens) = TimestampDetector::detect_and_replace(no_sep);
    assert_eq!(result, no_sep);
    assert!(tokens.is_empty());
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
        assert_eq!(&result, input, "false positive rewritten: {input}");
        assert!(
            tokens.is_empty(),
            "no timestamp token expected in {input:?}, got {tokens:?}"
        );
    }
}

#[test]
fn test_binary_data_safety() {
    // Test with binary-like data that might contain timestamp-like patterns
    let binary_like = "ÿþ2025\x00\x01\x0229T10:15:30Zÿþ";
    let (result, tokens) = TimestampDetector::detect_and_replace(binary_like);

    // Control bytes break the timestamp shape: input passes through
    // unchanged with no tokens (and no panic).
    assert_eq!(result, binary_like);
    assert!(tokens.is_empty());
}
