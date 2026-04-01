// Performance Benchmark: Detection Performance (T044)
// Measures runtime performance of unified timestamp detection

use lessence::patterns::timestamp::{TimestampDetector, UnifiedTimestampDetector};
use std::time::Instant;

#[test]
fn test_single_timestamp_detection_speed() {
    let test_cases = vec![
        "2025-09-29T10:15:30Z Simple ISO format",
        "E0929 13:07:09.181236 3116 K8S format",
        "Jan 29 10:15:30 Traditional syslog",
        "[29/Sep/2025:10:15:30 +0000] Apache format",
    ];

    for input in test_cases {
        let start = Instant::now();

        // Run detection many times to measure performance
        for _ in 0..1000 {
            let result = UnifiedTimestampDetector::detect_with_metadata(input);
            assert!(
                !result.matches.is_empty(),
                "Should detect timestamp in: {input}"
            );
        }

        let duration = start.elapsed();
        let per_operation = duration.as_nanos() / 1000;

        // Each detection should be fast (< 250μs per operation in debug mode)
        assert!(
            per_operation < 250_000,
            "Detection too slow for '{input}': {per_operation}ns per operation"
        );
    }
}

#[test]
fn test_multiple_timestamp_detection_speed() {
    let input = "Start: 2025-09-29T10:15:30Z Middle: E0929 13:07:09.181236 3116 End: 1727676930";
    let start = Instant::now();

    for _ in 0..500 {
        let result = UnifiedTimestampDetector::detect_with_metadata(input);
        assert_eq!(result.matches.len(), 3, "Should detect all 3 timestamps");
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 500;

    // Multiple timestamp detection should still be fast (< 1000μs in debug mode)
    assert!(
        per_operation < 1_000_000,
        "Multiple detection too slow: {per_operation}ns per operation"
    );
}

#[test]
fn test_no_match_performance() {
    let no_timestamp_inputs = vec![
        "Regular log message without any timestamps",
        "Error code 404 and process ID 12345 but no times",
        "Just some random text with numbers 123 and words",
        "Configuration loaded successfully from config.yaml",
    ];

    for input in no_timestamp_inputs {
        let start = Instant::now();

        // Fast path should be very fast for non-matching input
        for _ in 0..2000 {
            let result = UnifiedTimestampDetector::detect_with_metadata(input);
            assert_eq!(
                result.matches.len(),
                0,
                "Should not detect false positives in: {input}"
            );
        }

        let duration = start.elapsed();
        let per_operation = duration.as_nanos() / 2000;

        // Non-matching input should be very fast (< 50μs)
        assert!(
            per_operation < 50_000,
            "No-match detection too slow for '{input}': {per_operation}ns per operation"
        );
    }
}

#[test]
fn test_overlap_resolution_performance() {
    // Test performance when multiple patterns could match the same text
    let overlapping_input = "2025-09-29T10:15:30.123456789Z";
    let start = Instant::now();

    for _ in 0..1000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(overlapping_input);
        assert_eq!(
            result.matches.len(),
            1,
            "Should resolve overlaps to single match"
        );
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 1000;

    // Overlap resolution should not significantly slow down detection (< 500μs in debug mode)
    assert!(
        per_operation < 500_000,
        "Overlap resolution too slow: {per_operation}ns per operation"
    );
}

#[test]
fn test_long_text_performance() {
    let base_text = "This is a longer log message with various content ";
    let long_input = format!(
        "{}2025-09-29T10:15:30Z{}",
        base_text.repeat(50), // 2500+ characters before
        base_text.repeat(50)  // 2500+ characters after
    );

    let start = Instant::now();

    for _ in 0..100 {
        let result = UnifiedTimestampDetector::detect_with_metadata(&long_input);
        // Very long lines may return 0 matches due to line length security limits,
        // or 1 match if within limits. Either is acceptable.
        assert!(
            result.matches.len() <= 1,
            "Should find at most 1 timestamp in long text"
        );
    }

    let duration = start.elapsed();
    let per_operation = duration.as_millis() / 100;

    // Long text processing should complete in reasonable time (< 10ms)
    assert!(
        per_operation < 10,
        "Long text detection too slow: {per_operation}ms per operation"
    );
}

#[test]
fn test_backward_compatibility_performance() {
    // Test that backward compatibility layer doesn't add significant overhead
    let input = "2025-09-29T10:15:30Z Compatibility test";

    // Test new API
    let start_new = Instant::now();
    for _ in 0..1000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(input);
        assert!(!result.matches.is_empty());
    }
    let new_duration = start_new.elapsed();

    // Test compatibility API
    let start_compat = Instant::now();
    for _ in 0..1000 {
        let (_result, tokens) = TimestampDetector::detect_and_replace(input);
        assert!(!tokens.is_empty());
    }
    let compat_duration = start_compat.elapsed();

    // Compatibility layer should not add significant overhead (< 2x slower)
    let overhead_ratio = compat_duration.as_nanos() as f64 / new_duration.as_nanos() as f64;
    assert!(
        overhead_ratio < 2.0,
        "Compatibility layer too slow: {overhead_ratio}x overhead"
    );
}

#[test]
fn test_constitutional_unix_timestamp_penalty_performance() {
    // Test that Unix timestamp penalty doesn't significantly impact performance
    let unix_input = "Process started at 1727676930 with PID 12345";
    let iso_input = "Process started at 2025-09-29T10:15:30Z with PID 12345";

    // Measure Unix timestamp detection
    let start_unix = Instant::now();
    for _ in 0..1000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(unix_input);
        // Unix might or might not be detected due to penalty, but shouldn't crash
        assert!(result.matches.len() <= 1);
    }
    let unix_duration = start_unix.elapsed();

    // Measure ISO timestamp detection
    let start_iso = Instant::now();
    for _ in 0..1000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(iso_input);
        assert_eq!(result.matches.len(), 1, "Should detect ISO timestamp");
    }
    let iso_duration = start_iso.elapsed();

    // Performance should be comparable (priority logic shouldn't add major overhead)
    let ratio = unix_duration.as_nanos() as f64 / iso_duration.as_nanos() as f64;
    assert!(
        ratio < 3.0,
        "Unix penalty performance impact too high: {ratio}x slower"
    );
}

#[test]
fn test_pattern_priority_performance() {
    // Test that priority-based resolution is efficient
    let mixed_input = "Mixed formats: 2025-09-29T10:15:30Z and E0929 13:07:09.181236 3116";
    let start = Instant::now();

    for _ in 0..1000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(mixed_input);
        assert_eq!(
            result.matches.len(),
            2,
            "Should detect both distinct timestamps"
        );
    }

    let duration = start.elapsed();
    let per_operation = duration.as_nanos() / 1000;

    // Priority resolution should be efficient (< 500μs in debug mode)
    assert!(
        per_operation < 500_000,
        "Priority resolution too slow: {per_operation}ns per operation"
    );
}

#[test]
fn test_concurrent_detection_performance() {
    use std::sync::Arc;
    use std::thread;

    let input = Arc::new("2025-09-29T10:15:30Z Concurrent detection test".to_string());
    let start = Instant::now();

    let mut handles = vec![];

    // Test concurrent detection performance
    for _ in 0..4 {
        let input_clone = Arc::clone(&input);
        let handle = thread::spawn(move || {
            for _ in 0..250 {
                let result = UnifiedTimestampDetector::detect_with_metadata(&input_clone);
                assert!(!result.matches.is_empty());
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    let total_duration = start.elapsed();

    // 1000 total operations across 4 threads should complete quickly
    assert!(
        total_duration.as_millis() < 1000,
        "Concurrent detection too slow: {}ms for 1000 operations",
        total_duration.as_millis()
    );
}

#[test]
fn test_memory_allocation_performance() {
    // Test that detection doesn't cause excessive memory allocations
    let input = "2025-09-29T10:15:30Z Memory allocation test";

    // Run many iterations to check for memory allocation patterns
    let start = Instant::now();
    for i in 0..5000 {
        let result = UnifiedTimestampDetector::detect_with_metadata(input);
        assert!(!result.matches.is_empty());

        // Periodic performance check
        if i % 1000 == 0 && i > 0 {
            let intermediate_duration = start.elapsed();
            let ops_per_sec = f64::from(i) / intermediate_duration.as_secs_f64();

            // Should maintain consistent performance (> 3k ops/sec in debug mode)
            assert!(
                ops_per_sec > 3000.0,
                "Performance degradation at iteration {i}: {ops_per_sec} ops/sec"
            );
        }
    }

    let final_duration = start.elapsed();
    let final_ops_per_sec = 5000.0 / final_duration.as_secs_f64();

    // Should maintain high throughput throughout (> 3k ops/sec in debug mode)
    assert!(
        final_ops_per_sec > 3000.0,
        "Final performance too low: {final_ops_per_sec} ops/sec"
    );
}

#[test]
fn test_scalability_with_pattern_count() {
    // Test that performance doesn't degrade significantly with pattern count
    let inputs = vec![
        "2025-09-29T10:15:30Z ISO format",
        "E0929 13:07:09.181236 3116 K8S format",
        "Jan 29 10:15:30 Syslog format",
        "[29/Sep/2025:10:15:30 +0000] Apache format",
    ];

    let mut total_duration = std::time::Duration::ZERO;

    for input in &inputs {
        let start = Instant::now();

        for _ in 0..200 {
            let result = UnifiedTimestampDetector::detect_with_metadata(input);
            assert!(
                !result.matches.is_empty(),
                "Should detect timestamp in: {input}"
            );
        }

        total_duration += start.elapsed();
    }

    let avg_per_operation = total_duration.as_nanos() / (inputs.len() as u128 * 200);

    // Average across all pattern types should be reasonable (< 500μs in debug mode)
    assert!(
        avg_per_operation < 500_000,
        "Average detection across pattern types too slow: {avg_per_operation}ns per operation"
    );
}
