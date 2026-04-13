// Performance Tests: Timestamp Detection (T044)
//
// Tests that detection scales linearly with input complexity.
// Relative-comparison tests (API overhead, compat layer) test that
// one approach isn't dramatically slower than another.
// All tests are immune to CPU contention from parallel test runs.

use lessence::patterns::timestamp::{TimestampDetector, UnifiedTimestampDetector};
use std::time::Instant;

fn measure_detect(input: &str, iters: u32) -> std::time::Duration {
    for _ in 0..iters / 10 {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }
    let start = Instant::now();
    for _ in 0..iters {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }
    start.elapsed()
}

#[test]
fn test_single_timestamp_detection_scales_linearly() {
    let small = format!("{}2025-09-29T10:15:30Z end", "Regular log text ".repeat(10));
    let large = format!("{}2025-09-29T10:15:30Z end", "Regular log text ".repeat(40));

    crate::common::assert_linear_scaling("single_timestamp", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_multiple_timestamp_detection_scales_linearly() {
    let build = |count: usize| {
        let mut line = String::new();
        for i in 0..count {
            line.push_str(&format!("2025-09-29T10:{:02}:30Z event{i} ", i % 60));
        }
        line
    };
    let small = build(3);
    let large = build(12);

    crate::common::assert_linear_scaling("multiple_timestamps", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_long_text_performance() {
    let base = "This is a longer log message with various content ";
    let small = format!("{}2025-09-29T10:15:30Z{}", base.repeat(12), base.repeat(12),);
    let large = format!("{}2025-09-29T10:15:30Z{}", base.repeat(48), base.repeat(48),);

    crate::common::assert_linear_scaling("long_text", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_overlap_resolution_performance() {
    // Overlapping timestamps should still be linear
    let build = |count: usize| {
        let mut line = String::new();
        for _ in 0..count {
            line.push_str("2025-09-29T10:15:30.123456789Z ");
        }
        line
    };
    let small = build(3);
    let large = build(12);

    crate::common::assert_linear_scaling("overlap", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_no_match_performance() {
    // Non-matching input should be fast — and linear with input size
    let small = "Regular log message without timestamps. Error 404 process 12345. ".repeat(10);
    let large = "Regular log message without timestamps. Error 404 process 12345. ".repeat(40);

    crate::common::assert_linear_scaling("no_match", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_pattern_priority_performance() {
    let build = |count: usize| {
        let mut line = String::new();
        for _ in 0..count {
            line.push_str("2025-09-29T10:15:30Z and E0929 13:07:09.181236 3116 ");
        }
        line
    };
    let small = build(2);
    let large = build(8);

    crate::common::assert_linear_scaling("priority", &small, &large, |input| {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    });
}

#[test]
fn test_backward_compatibility_performance() {
    // Compatibility layer should not add significant overhead (< 2x)
    let input = "2025-09-29T10:15:30Z Compatibility test";
    let iters = 2000;

    let start_new = Instant::now();
    for _ in 0..iters {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }
    let new_duration = start_new.elapsed();

    let start_compat = Instant::now();
    for _ in 0..iters {
        let _ = TimestampDetector::detect_and_replace(input);
    }
    let compat_duration = start_compat.elapsed();

    let ratio = compat_duration.as_nanos() as f64 / new_duration.as_nanos().max(1) as f64;
    assert!(
        ratio < 2.0,
        "Compatibility layer too slow: {ratio:.1}x overhead"
    );
}

#[test]
fn test_unix_timestamp_penalty_performance() {
    // Unix timestamp penalty should not add major overhead vs ISO
    let unix_input = "Process started at 1727676930 with PID 12345";
    let iso_input = "Process started at 2025-09-29T10:15:30Z with PID 12345";
    let iters = 2000;

    let time_unix = measure_detect(unix_input, iters);
    let time_iso = measure_detect(iso_input, iters);

    let ratio = time_unix.as_nanos() as f64 / time_iso.as_nanos().max(1) as f64;
    assert!(
        ratio < 3.0,
        "Unix penalty too high: {ratio:.1}x slower than ISO"
    );
}

#[test]
fn test_concurrent_detection_correctness() {
    // Verify detection is thread-safe (correctness, not speed)
    use std::sync::Arc;
    use std::thread;

    let input = Arc::new("2025-09-29T10:15:30Z Concurrent test".to_string());
    let mut handles = vec![];

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

    for handle in handles {
        handle.join().expect("Thread should complete");
    }
}

#[test]
fn test_memory_allocation_consistency() {
    // Verify detection doesn't degrade over many iterations.
    // Measure first batch vs last batch — ratio should be ~1.0.
    let input = "2025-09-29T10:15:30Z Memory allocation test";
    let batch = 1000;

    // Warmup
    for _ in 0..batch {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }

    let start_early = Instant::now();
    for _ in 0..batch {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }
    let time_early = start_early.elapsed();

    // Run more iterations to age any allocator effects
    for _ in 0..5000 {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }

    let start_late = Instant::now();
    for _ in 0..batch {
        let _ = UnifiedTimestampDetector::detect_with_metadata(input);
    }
    let time_late = start_late.elapsed();

    let ratio = time_late.as_nanos() as f64 / time_early.as_nanos().max(1) as f64;
    assert!(
        ratio < 2.0,
        "Performance degraded over iterations: early batch vs late batch ratio {ratio:.2}x"
    );
}

#[test]
fn test_scalability_with_pattern_count() {
    // More pattern types in input should scale linearly
    let inputs_1 = vec!["2025-09-29T10:15:30Z ISO only"];
    let inputs_4 = vec![
        "2025-09-29T10:15:30Z ISO format",
        "E0929 13:07:09.181236 3116 K8S format",
        "Jan 29 10:15:30 Syslog format",
        "[29/Sep/2025:10:15:30 +0000] Apache format",
    ];

    let iters = 500;

    let start = Instant::now();
    for _ in 0..iters {
        for input in &inputs_1 {
            let _ = UnifiedTimestampDetector::detect_with_metadata(input);
        }
    }
    let time_1 = start.elapsed();

    let start = Instant::now();
    for _ in 0..iters {
        for input in &inputs_4 {
            let _ = UnifiedTimestampDetector::detect_with_metadata(input);
        }
    }
    let time_4 = start.elapsed();

    let ratio = time_4.as_nanos() as f64 / time_1.as_nanos().max(1) as f64;
    // 4 patterns should take ~4x, not 16x
    assert!(
        ratio < 8.0,
        "Detection doesn't scale linearly with pattern count: {ratio:.1}x for 4 patterns"
    );
}
