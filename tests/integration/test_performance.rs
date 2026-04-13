// Integration Test: Performance Benchmarks (T014)
// Validates performance characteristics and regression prevention.
//
// All timing tests use the scaling-ratio pattern: measure at N and 4N,
// assert ratio < 8.0. This tests algorithmic complexity (O(n) vs O(n²))
// and is immune to CPU speed, contention, and debug/release differences.

use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_single_timestamp_scales_linearly() {
    let small = "2025-09-29T10:15:30Z Simple log message".to_string();
    let large = format!("{small} {small} {small} {small}");

    crate::common::assert_linear_scaling("single_timestamp", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_multiple_timestamps_scales_linearly() {
    let base = "Start: 2025-09-29T10:15:30Z Middle: Jan 29 10:15:30 End: 1727676930.123";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("multiple_timestamps", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_no_timestamp_scales_linearly() {
    let base = "Regular log message without any timestamp patterns to detect";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("no_timestamp", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_long_line_scales_linearly() {
    let base_msg = "This is a longer log message with more content ";
    let small = format!(
        "{}2025-09-29T10:15:30Z{}",
        base_msg.repeat(5),
        base_msg.repeat(5)
    );
    let large = format!(
        "{}2025-09-29T10:15:30Z{}",
        base_msg.repeat(20),
        base_msg.repeat(20)
    );

    crate::common::assert_linear_scaling("long_line", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_pattern_compilation_succeeds() {
    // Verify patterns load correctly and have expected count
    use lessence::patterns::timestamp::TimestampRegistry;
    let registry = TimestampRegistry::new();
    let patterns = registry.get_patterns();
    assert!(
        patterns.len() >= 30,
        "Should have sufficient patterns, got {}",
        patterns.len()
    );
}

#[test]
fn test_memory_usage_stability() {
    let input = "2025-09-29T10:15:30Z Memory test message";

    // Run many iterations to check for panics or crashes
    for _ in 0..10000 {
        let (_result, _tokens) = TimestampDetector::detect_and_replace(input);
    }
}

#[test]
fn test_concurrent_performance() {
    use std::sync::Arc;
    use std::thread;

    let input = Arc::new("2025-09-29T10:15:30Z Concurrent test message".to_string());

    let mut handles = vec![];

    // Spawn multiple threads — just verify no panics or deadlocks
    for _ in 0..4 {
        let input_clone = Arc::clone(&input);
        let handle = thread::spawn(move || {
            for _ in 0..250 {
                let (_result, _tokens) = TimestampDetector::detect_and_replace(&input_clone);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete without panic");
    }
}

#[test]
fn test_regex_cache_effectiveness() {
    use std::time::Instant;

    let test_inputs = vec![
        "2025-09-29T10:15:30Z ISO format",
        "E0929 13:07:09.181236 3116 K8S format",
        "Jan 29 10:15:30 Syslog format",
        "[29/Sep/2025:10:15:30 +0000] Apache format",
        "timestamp=1727676930 Unix format",
    ];

    // First run — may include lazy init cost
    let start1 = Instant::now();
    for input in &test_inputs {
        let _ = TimestampDetector::detect_and_replace(input);
    }
    let first_run = start1.elapsed();

    // Second run — should benefit from cached patterns
    let start2 = Instant::now();
    for input in &test_inputs {
        let _ = TimestampDetector::detect_and_replace(input);
    }
    let second_run = start2.elapsed();

    // Second run should not be dramatically slower than first
    assert!(
        second_run <= first_run * 3,
        "Pattern caching not effective: first={}μs, second={}μs",
        first_run.as_micros(),
        second_run.as_micros()
    );
}
