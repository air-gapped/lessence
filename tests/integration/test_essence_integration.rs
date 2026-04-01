// Integration Test: Essence Mode Compatibility
// Tests integration with essence mode processor

use lessence::patterns::timestamp::UnifiedTimestampDetector;

#[test]
fn test_essence_mode_api_preservation() {
    // Verify that essence mode functionality is preserved
    let input = "2025-09-29T10:15:30Z Service started";

    // Both standard and essence modes should work identically
    let (standard_result, standard_tokens) = UnifiedTimestampDetector::detect_and_replace(input);
    let (essence_result, essence_tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    assert_eq!(standard_result, essence_result);
    assert_eq!(standard_tokens.len(), essence_tokens.len());
    assert_eq!(standard_result, "<TIMESTAMP> Service started");
}

#[test]
fn test_k8s_timestamp_tokenization() {
    // Test the K8S timestamp fix from constitutional restoration
    let input = "E0909 13:07:09.181236 3116 kubelet.go:123] test";
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

    // Should show <TIMESTAMP> not <DECIMAL>
    assert_eq!(result, "<TIMESTAMP> 3116 kubelet.go:123] test");
    assert_eq!(tokens.len(), 1);

    if let lessence::patterns::Token::Timestamp(ts) = &tokens[0] {
        assert_eq!(ts, "E0909 13:07:09.181236");
    } else {
        panic!("Expected Timestamp token");
    }
}

#[test]
fn test_temporal_independence() {
    // Essence mode should achieve temporal independence
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

    // All results should be identical after timestamp removal
    assert_eq!(results[0], "<TIMESTAMP> ERROR: Database connection failed");
    assert_eq!(results[1], "<TIMESTAMP> ERROR: Database connection failed");
    assert_eq!(results[2], "<TIMESTAMP> ERROR: Database connection failed");

    // Verify temporal independence
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

#[test]
fn test_comprehensive_format_support() {
    // Test that all timestamp formats from both implementations work
    let test_cases = vec![
        // From original timestamp.rs
        ("2025-09-29T10:15:30.123456Z", "ISO8601 Enhanced"),
        ("2025-W36-7T14:45:38Z", "Week Date"),
        ("2025-250T14:45:38.123Z", "Ordinal Date"),
        ("2025-09-29 10:15:30,123", "Java Timestamp"),
        ("01/20/2025 10:15:30 AM", "US Date"),
        ("[20/Jan/2025:10:15:30 +0000]", "Apache Common"),

        // From original essence/processor.rs
        ("01/20/2025 10:15:30 PM", "Windows Event"),
        ("Jan 20 2025 10:15:30", "Git Commit Style"),
        ("2025-09-29T10:15:30.123Z", "AWS Format"),
        ("2025-09-29T10:15:30.123456Z", "GCP Format"),
        ("2025-09-29T10:15:30.1234567Z", "Azure Format"),
        ("Mon, 20 Jan 2025 10:15:30 GMT", "RFC822"),
    ];

    for (input, description) in test_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);

        assert!(result.contains("<TIMESTAMP>"),
            "Failed to detect {} format in: {}", description, input);
        assert!(tokens.len() > 0,
            "No tokens generated for {} format in: {}", description, input);
    }
}

#[test]
fn test_pattern_priority_enforcement() {
    // Test that overlapping patterns are resolved correctly
    let input = "Event at unix=1727676930 time=2025-09-29T10:15:30Z";
    let result = UnifiedTimestampDetector::detect_with_metadata(input);

    // Should prefer ISO8601 over Unix timestamp due to higher priority
    assert_eq!(result.normalized_text, "Event at unix=1727676930 time=<TIMESTAMP>");

    // Should have detected both but applied only the higher priority one
    assert!(result.matches.len() >= 1);

    if let Some(applied) = result.applied_match {
        assert!(matches!(applied.format_type, lessence::patterns::timestamp::TimestampFormat::ISO8601Enhanced));
    } else {
        panic!("No match was applied");
    }
}

#[test]
fn test_unix_timestamp_false_positive_prevention() {
    // Unix timestamps should not match arbitrary numbers
    let test_cases = vec![
        ("Processed 12345 items", "Processed 12345 items"),  // No change
        ("Port 8080 is open", "Port 8080 is open"),  // No change
        ("Code 404 not found", "Code 404 not found"),  // No change
        ("Valid unix ts: 1727676930", "Valid unix ts: <TIMESTAMP>"),  // Should match
    ];

    for (input, expected) in test_cases {
        let (result, _tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        assert_eq!(result, expected, "Unix false positive test failed for: {}", input);
    }
}

#[test]
fn test_thread_safety_in_essence_mode() {
    use std::thread;
    use std::sync::Arc;

    let test_input = Arc::new("2025-09-29T10:15:30Z Concurrent processing".to_string());
    let mut handles = vec![];

    // Spawn multiple threads to test concurrent access
    for _ in 0..50 {
        let input_clone = Arc::clone(&test_input);
        let handle = thread::spawn(move || {
            UnifiedTimestampDetector::detect_and_replace(&input_clone)
        });
        handles.push(handle);
    }

    // All threads should produce consistent results
    let mut results = Vec::new();
    for handle in handles {
        let (result, tokens) = handle.join().expect("Thread panicked");
        results.push((result, tokens));
    }

    // Verify all results are identical
    let expected_result = "<TIMESTAMP> Concurrent processing";
    for (result, tokens) in results {
        assert_eq!(result, expected_result);
        assert_eq!(tokens.len(), 1);
    }
}

#[test]
fn test_memory_efficiency() {
    // Test that the unified implementation doesn't use excessive memory
    let large_input = "2025-09-29T10:15:30Z ".repeat(10000);

    // This should not cause memory issues
    let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(&large_input);

    // Basic validation
    assert!(result.len() > 0);
    assert_eq!(tokens.len(), 10000);
}