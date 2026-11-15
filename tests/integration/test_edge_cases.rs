use lessence::patterns::timestamp::UnifiedTimestampDetector;

#[test]
fn test_empty_input() {
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace("");
    assert_eq!(result, "");
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_whitespace_only() {
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace("   \t\n  ");
    assert_eq!(result, "   \t\n  ");
    assert_eq!(tokens.len(), 0);
}

#[test]
fn test_very_long_line() {
    let prefix = "Very long line ".repeat(1000);
    let input = format!("{prefix}2025-09-29T10:15:30Z End");
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(&input);

    assert!(result.ends_with("<TIMESTAMP> End"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_malformed_timestamps() {
    let shape_valid_impossible_calendar_dates = [
        "2025-13-45T25:99:99Z",
        "2025-02-30T10:15:30Z",
        "2025-09-29T25:15:30Z",
    ];
    let missing_or_wrong_separators = ["20250929T101530Z", "2025/09/29T10:15:30Z"];

    for input in &shape_valid_impossible_calendar_dates {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(
            result, "<TIMESTAMP>",
            "the detector checks shape, not the calendar, so an impossible date still folds as a timestamp: {input}"
        );
        assert_eq!(tokens.len(), 1);
    }
    for input in &missing_or_wrong_separators {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(
            &result, input,
            "wrong-separator input matches no format and passes through byte-identical"
        );
        assert!(tokens.is_empty());
    }
}

#[test]
fn test_unicode_timestamps() {
    let input = "Événement à 2025-09-29T10:15:30Z terminé";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

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
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
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
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert!(result.contains("<TIMESTAMP>"));
    assert_eq!(tokens.len(), 1);
}

#[test]
fn test_timestamp_at_boundaries() {
    let test_cases = vec![
        "2025-09-29T10:15:30Z",
        "2025-09-29T10:15:30Z ",
        " 2025-09-29T10:15:30Z",
    ];

    for input in test_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert!(
            result.contains("<TIMESTAMP>"),
            "Should detect at boundaries: {input}"
        );
        assert_eq!(tokens.len(), 1);
    }

    let no_sep = "Start2025-09-29T10:15:30ZEnd";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(no_sep);
    assert_eq!(
        result, no_sep,
        "a timestamp with no word boundary on either side is not detected"
    );
    assert!(tokens.is_empty());
}

#[test]
fn test_repeated_timestamps() {
    let input = "2025-09-29T10:15:30Z 2025-09-29T10:15:30Z 2025-09-29T10:15:30Z";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(result, "<TIMESTAMP> <TIMESTAMP> <TIMESTAMP>");
    assert_eq!(tokens.len(), 3);
}

#[test]
fn test_overlapping_pattern_candidates() {
    let input = "2025-09-29T10:15:30.123456789Z";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(result, "<TIMESTAMP>");
    assert_eq!(tokens.len(), 1);

    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert!(ts.len() > 20, "Should match full precision timestamp");
    }
}

#[test]
fn test_false_positive_prevention() {
    let false_positives = vec![
        "Process ID 12345",
        "Port 8080 is open",
        "Error code 404",
        "Version 2025.09.29",
        "File size 1727676930 bytes",
    ];

    for input in false_positives {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(&result, input, "false positive rewritten: {input}");
        assert!(
            tokens.is_empty(),
            "no timestamp token expected in {input:?}, got {tokens:?}"
        );
    }
}

#[test]
fn test_binary_data_safety() {
    let binary_like = "ÿþ2025\x00\x01\x0229T10:15:30Zÿþ";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(binary_like);

    assert_eq!(
        result, binary_like,
        "control bytes break the timestamp shape, so the input passes through unchanged"
    );
    assert!(tokens.is_empty());
}
