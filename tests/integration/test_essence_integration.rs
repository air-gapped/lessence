use lessence::patterns::timestamp::UnifiedTimestampDetector;

#[test]
fn test_essence_mode_api_preservation() {
    let input = "2025-09-29T10:15:30Z Service started";

    let (standard_result, standard_tokens) = UnifiedTimestampDetector::detect_and_replace(input);
    let (essence_result, essence_tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(standard_result, essence_result);
    assert_eq!(standard_tokens.len(), essence_tokens.len());
    assert_eq!(standard_result, "<TIMESTAMP> Service started");
}

#[test]
fn test_k8s_timestamp_tokenization() {
    let input = "E0909 13:07:09.181236 3116 kubelet.go:123] test";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(
        result, "<TIMESTAMP> 3116 kubelet.go:123] test",
        "a klog header is one <TIMESTAMP>, never a <DECIMAL>"
    );
    assert_eq!(tokens.len(), 1);

    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert_eq!(ts, "E0909 13:07:09.181236");
    } else {
        panic!("Expected Timestamp token");
    }
}

#[test]
fn test_temporal_independence() {
    let inputs = vec![
        "2025-09-26T10:15:00Z ERROR: Database connection failed",
        "2025-09-26T10:15:01Z ERROR: Database connection failed",
        "2025-09-27T15:30:00Z ERROR: Database connection failed",
    ];

    let mut results = Vec::new();
    for input in inputs {
        let (result, _tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        results.push(result);
    }

    assert_eq!(results[0], "<TIMESTAMP> ERROR: Database connection failed");
    assert_eq!(results[1], "<TIMESTAMP> ERROR: Database connection failed");
    assert_eq!(results[2], "<TIMESTAMP> ERROR: Database connection failed");

    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn test_comprehensive_format_support() {
    let test_cases = vec![
        ("2025-09-29T10:15:30.123456Z", "ISO8601 Enhanced"),
        ("2025-W36-7T14:45:38Z", "Week Date"),
        ("2025-250T14:45:38.123Z", "Ordinal Date"),
        ("2025-09-29 10:15:30,123", "Java Timestamp"),
        ("01/20/2025 10:15:30 AM", "US Date"),
        ("[20/Jan/2025:10:15:30 +0000]", "Apache Common"),
        ("01/20/2025 10:15:30 PM", "Windows Event"),
        ("Jan 20 2025 10:15:30", "Git Commit Style"),
        ("2025-09-29T10:15:30.123Z", "AWS Format"),
        ("2025-09-29T10:15:30.123456Z", "GCP Format"),
        ("2025-09-29T10:15:30.1234567Z", "Azure Format"),
        ("Mon, 20 Jan 2025 10:15:30 GMT", "RFC822"),
    ];

    for (input, description) in test_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

        assert!(
            result.contains("<TIMESTAMP>"),
            "Failed to detect {description} format in: {input}"
        );
        assert!(
            !tokens.is_empty(),
            "No tokens generated for {description} format in: {input}"
        );
    }
}

#[test]
fn test_pattern_priority_enforcement() {
    let input = "Event at unix=1727676930 time=2025-09-29T10:15:30Z";
    let result = UnifiedTimestampDetector::detect_with_metadata(input);

    assert!(
        result.normalized_text.contains("<TIMESTAMP>"),
        "Should detect timestamp in: {input}"
    );
    assert!(!result.matches.is_empty(), "Should have at least one match");
}

#[test]
fn test_unix_timestamp_false_positive_prevention() {
    let no_match_cases = vec![
        "Processed 12345 items",
        "Port 8080 is open",
        "Code 404 not found",
    ];

    for input in no_match_cases {
        let (result, _tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(result, input, "Should not match arbitrary numbers: {input}");
    }
}

#[test]
fn test_thread_safety_in_essence_mode() {
    use std::sync::Arc;
    use std::thread;

    let test_input = Arc::new("2025-09-29T10:15:30Z Concurrent processing".to_string());
    let mut handles = vec![];

    for _ in 0..50 {
        let input_clone = Arc::clone(&test_input);
        let handle =
            thread::spawn(move || UnifiedTimestampDetector::detect_and_replace(&input_clone));
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let (result, tokens) = handle.join().expect("Thread panicked");
        results.push((result, tokens));
    }

    let expected_result = "<TIMESTAMP> Concurrent processing";
    for (result, tokens) in results {
        assert_eq!(result, expected_result);
        assert_eq!(tokens.len(), 1);
    }
}

#[test]
fn test_memory_efficiency() {
    let large_input = "2025-09-29T10:15:30Z ".repeat(10000);

    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(&large_input);

    assert!(!result.is_empty());
    assert_eq!(tokens.len(), 10000);
}
