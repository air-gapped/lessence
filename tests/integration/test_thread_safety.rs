use lessence::patterns::timestamp::UnifiedTimestampDetector;
use std::sync::Arc;
use std::thread;

#[test]
fn test_concurrent_pattern_access() {
    let mut handles = vec![];

    for _ in 0..20 {
        let handle = thread::spawn(|| lessence::patterns::timestamp::patterns().len());
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let result = handle.join().expect("Thread should complete successfully");
        results.push(result);
    }

    assert!(!results.is_empty(), "Should have thread results");
    let first_result = results[0];
    for result in &results {
        assert_eq!(
            *result, first_result,
            "All threads should see same pattern count"
        );
    }
    assert!(first_result >= 30, "Should meet constitutional requirement");
}

#[test]
fn test_concurrent_detection_operations() {
    let test_inputs = Arc::new(vec![
        "2025-09-29T10:15:30Z Test message 1",
        "E0929 13:07:09.181236 3116 Test message 2",
        "Jan 29 10:15:30 Test message 3",
        "timestamp=1727676930 Test message 4",
        "[29/Sep/2025:10:15:30 +0000] Test message 5",
    ]);

    let mut handles = vec![];

    for i in 0..50 {
        let inputs_clone = Arc::clone(&test_inputs);
        let handle = thread::spawn(move || {
            let input = &inputs_clone[i % inputs_clone.len()];
            let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
            (result, tokens.len())
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let (result, token_count) = handle.join().expect("Thread should complete successfully");
        results.push((result, token_count));
    }

    for (result, token_count) in results {
        assert!(!result.is_empty(), "Result should not be empty");
        assert!(
            result.contains("<TIMESTAMP>") || token_count == 0,
            "Should either have timestamp or no tokens"
        );
        assert!(token_count <= 5, "Should not have excessive tokens");
    }
}

#[test]
fn test_registry_thread_safety() {
    use lessence::patterns::timestamp::patterns;

    let mut handles = vec![];

    for _ in 0..10 {
        let handle = thread::spawn(|| patterns().len());
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let pattern_count = handle.join().expect("Thread should complete");
        results.push(pattern_count);
    }

    assert!(!results.is_empty(), "Should have results");
    let first = results[0];
    for count in &results {
        assert_eq!(
            *count, first,
            "the lazily initialised registry has the same pattern count in every thread"
        );
    }
}

#[test]
fn test_stress_concurrent_access() {
    let input = Arc::new("2025-09-29T10:15:30Z Stress test message".to_string());
    let mut handles = vec![];

    for _ in 0..100 {
        let input_clone = Arc::clone(&input);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(&input_clone);
                assert!(
                    result.contains("<TIMESTAMP>"),
                    "Should consistently detect timestamp"
                );
                assert_eq!(tokens.len(), 1, "Should consistently find one token");
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Stress test thread should complete successfully");
    }
}
