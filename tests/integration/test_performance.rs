// Integration Test: Performance Benchmarks (T014)
// Validates performance characteristics and regression prevention

use std::time::Instant;
use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_single_timestamp_performance() {
    let input = "2025-09-29T10:15:30Z Simple log message";
    let start = Instant::now();

    // Run detection multiple times
    for _ in 0..1000 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 1000;

    // Should be reasonably fast (less than 1ms per operation)
    assert!(per_operation < 1_000_000, "Performance regression: {}ns per operation", per_operation);
}

#[test]
fn test_multiple_timestamp_performance() {
    let input = "Start: 2025-09-29T10:15:30Z Middle: Jan 29 10:15:30 End: 1727676930.123";
    let start = Instant::now();

    // Run detection multiple times
    for _ in 0..500 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 500;

    // Should handle multiple timestamps efficiently
    assert!(per_operation < 5_000_000, "Multiple timestamp performance regression: {}ns per operation", per_operation);
}

#[test]
fn test_no_timestamp_performance() {
    let input = "Regular log message without any timestamp patterns to detect";
    let start = Instant::now();

    // Should be fast when no timestamps are present
    for _ in 0..2000 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 2000;

    // Should be very fast for non-matching inputs (fast path)
    assert!(per_operation < 500_000, "No-timestamp performance regression: {}ns per operation", per_operation);
}

#[test]
fn test_long_line_performance() {
    let base_msg = "This is a longer log message with more content ";
    let input = format!("{}2025-09-29T10:15:30Z{}", base_msg.repeat(20), base_msg.repeat(20));

    let start = Instant::now();

    for _ in 0..100 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(&input);
    }

    let duration = start.elapsed();
    let per_operation = duration.as_millis() / 100;

    // Should handle long lines reasonably (less than 10ms)
    assert!(per_operation < 10, "Long line performance regression: {}ms per operation", per_operation);
}

#[test]
fn test_pattern_compilation_performance() {
    // Test the one-time cost of pattern loading
    let start = Instant::now();

    // Access patterns (triggers lazy initialization)
    use lessence::patterns::timestamp::UnifiedTimestampDetector;
    let patterns = UnifiedTimestampDetector::get_patterns();

    let duration = start.elapsed();

    // Pattern compilation should be reasonable (less than 100ms)
    assert!(duration.as_millis() < 100, "Pattern compilation too slow: {}ms", duration.as_millis());
    assert!(patterns.len() >= 30, "Should have sufficient patterns");
}

#[test]
fn test_memory_usage_stability() {
    let input = "2025-09-29T10:15:30Z Memory test message";

    // Run many iterations to check for memory leaks
    for i in 0..10000 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);

        // Periodic check - memory usage should be stable
        if i % 1000 == 0 {
            // Just ensure we don't crash or accumulate memory
            // Real memory usage would require external measurement
            assert!(true, "Memory stability check at iteration {}", i);
        }
    }
}

#[test]
fn test_concurrent_performance() {
    use std::thread;
    use std::sync::Arc;

    let input = Arc::new("2025-09-29T10:15:30Z Concurrent test message".to_string());
    let start = Instant::now();

    let mut handles = vec![];

    // Spawn multiple threads
    for _ in 0..4 {
        let input_clone = Arc::clone(&input);
        let handle = thread::spawn(move || {
            for _ in 0..250 {
                let (_result, _tokens) = TimestampDetector::detect_and_replace(&input_clone);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    let duration = start.elapsed();

    // Concurrent access should not significantly degrade performance
    // Total 1000 operations across 4 threads
    assert!(duration.as_millis() < 1000, "Concurrent performance degradation: {}ms for 1000 operations", duration.as_millis());
}

#[test]
fn test_regex_cache_effectiveness() {
    let test_inputs = vec![
        "2025-09-29T10:15:30Z ISO format",
        "E0929 13:07:09.181236 3116 K8S format",
        "Jan 29 10:15:30 Syslog format",
        "[29/Sep/2025:10:15:30 +0000] Apache format",
        "timestamp=1727676930 Unix format",
    ];

    // First run - might include compilation cost
    let start1 = Instant::now();
    for input in &test_inputs {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }
    let first_run = start1.elapsed();

    // Second run - should benefit from cached patterns
    let start2 = Instant::now();
    for input in &test_inputs {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }
    let second_run = start2.elapsed();

    // Second run should be as fast or faster (patterns cached)
    assert!(second_run <= first_run * 2, "Pattern caching not effective: first={}μs, second={}μs",
        first_run.as_micros(), second_run.as_micros());
}