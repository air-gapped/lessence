// Integration Test: Performance Benchmarks (T014)
// Validates performance characteristics and regression prevention.
//
// All timing tests use the scaling-ratio pattern: measure at N and 4N,
// assert ratio < 8.0. This tests algorithmic complexity (O(n) vs O(n²))
// and is immune to CPU speed, contention, and debug/release differences.
//
// Coverage: every pattern detector + the full normalization pipeline.
// If a new detector is added, add a scaling test here.

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

// ---- Pattern detector scaling tests ----
// Each detector gets a scaling test with realistic input.
// The input triggers that detector's regex — not just pass-through.

#[test]
fn test_key_value_detection_scales_linearly() {
    use lessence::patterns::key_value::KeyValueDetector;
    let base = "timeout=30ms retries=3 cpu_usage=75% memory=512MB";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("key_value", &small, &large, |input| {
        let _ = KeyValueDetector::detect_and_replace(input);
    });
}

#[test]
fn test_bracket_context_detection_scales_linearly() {
    use lessence::patterns::bracket_context::BracketContextDetector;
    let base = "[error] [upstream] request failed with timeout";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("bracket_context", &small, &large, |input| {
        let _ = BracketContextDetector::detect_and_replace(input);
    });
}

#[test]
fn test_quoted_string_detection_scales_linearly() {
    use lessence::patterns::quoted::QuotedStringDetector;
    let base =
        r#"mount "csi-volume-abc123" pod "nginx-deployment-7d4b8c" uid "550e8400-e29b-41d4""#;
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("quoted_string", &small, &large, |input| {
        let _ = QuotedStringDetector::detect_and_replace(input);
    });
}

#[test]
fn test_structured_message_detection_scales_linearly() {
    use lessence::patterns::structured::StructuredMessageDetector;
    let base = r#"{"level":"error","component":"api-gateway","msg":"timeout"}"#;
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("structured_message", &small, &large, |input| {
        let _ = StructuredMessageDetector::detect_and_replace(input);
    });
}

#[test]
fn test_log_module_detection_scales_linearly() {
    use lessence::patterns::log_module::LogWithModuleDetector;
    let base = "[error] mod_ssl: SSL handshake failed for client";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("log_module", &small, &large, |input| {
        let _ = LogWithModuleDetector::detect_and_replace(input);
    });
}

#[test]
fn test_duration_detection_scales_linearly() {
    use lessence::patterns::duration::DurationDetector;
    let base = "took 150ms latency=2.5s cpu 45.7% size 512MB 0x7f8a9c buffer 4096bytes";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("duration", &small, &large, |input| {
        let _ = DurationDetector::detect_and_replace(input);
    });
}

#[test]
fn test_name_detection_scales_linearly() {
    use lessence::patterns::names::NameDetector;
    let base = "pod nginx-deployment-7d4b8c replica coredns-5644d7b6d9-abcde";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("names", &small, &large, |input| {
        let _ = NameDetector::detect_and_replace(input);
    });
}

#[test]
fn test_hash_detection_scales_linearly() {
    use lessence::patterns::hash::HashDetector;
    let base = "commit 5d41402abc4b2a76b9719d911017c592 sha256 a948904f2f0f479b8f8564e9d07ce8a2b1e6b4d28ff000b35a4e93f8c7a8e123";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("hash", &small, &large, |input| {
        let _ = HashDetector::detect_and_replace(input);
    });
}

#[test]
fn test_kubernetes_detection_scales_linearly() {
    use lessence::patterns::kubernetes::KubernetesDetector;
    let base = r#"pod kube-system/coredns-5644d7b6d9-abcde volume "kube-api-access-token-xyz""#;
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("kubernetes", &small, &large, |input| {
        let _ = KubernetesDetector::detect_and_replace(input);
    });
}

#[test]
fn test_http_status_detection_scales_linearly() {
    use lessence::patterns::http_status::HttpStatusDetector;
    let base = r#"10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET /api HTTP/1.1" 200 1234"#;
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("http_status", &small, &large, |input| {
        let _ = HttpStatusDetector::detect_and_replace(input);
    });
}

#[test]
fn test_process_detection_scales_linearly() {
    use lessence::patterns::process::ProcessDetector;
    let base = "[pid=12345] Thread-42 tid=0x7f8a9c001700 started";
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    crate::common::assert_linear_scaling("process", &small, &large, |input| {
        let _ = ProcessDetector::detect_and_replace(input);
    });
}

// ---- Full pipeline scaling test ----
// Tests the complete normalize → cluster → format path.

#[test]
fn test_full_pipeline_scales_linearly() {
    use lessence::config::Config;
    use lessence::normalize::Normalizer;

    let base = r#"2025-01-01T10:00:00Z [error] 10.0.0.1:8080 timeout=30ms pod kube-system/nginx-abc123 "volume-data""#;
    let small = base.to_string();
    let large = format!("{base} {base} {base} {base}");

    let config = Config::default();
    let normalizer = Normalizer::new(config);

    crate::common::assert_linear_scaling("full_pipeline", &small, &large, |input| {
        let _ = normalizer.normalize_line(input.to_string());
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
