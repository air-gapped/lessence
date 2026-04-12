// Contract Test: Constitutional Compliance for Unified Timestamp System

use lessence::patterns::timestamp::{
    TimestampFormat, TimestampRegistry, UnifiedTimestampDetector,
};

#[test]
fn test_pattern_count_constitutional_requirement() {
    let registry = TimestampRegistry::new();
    let patterns = registry.get_patterns();
    assert!(
        patterns.len() >= 30,
        "Constitutional violation: Must have 30+ patterns, found {}",
        patterns.len()
    );
}

#[test]
fn test_thread_safety_constitutional_requirement() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for _ in 0..20 {
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let (result, tokens) =
                    UnifiedTimestampDetector::detect_and_replace("2025-09-29T10:15:30Z Test");
                assert!(result.contains("<TIMESTAMP>"));
                assert_eq!(tokens.len(), 1);
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked — thread safety violation");
    }

    assert_eq!(counter.load(Ordering::SeqCst), 2000);
}

#[test]
fn test_pattern_completeness_constitutional_requirement() {
    let registry = TimestampRegistry::new();
    let patterns = registry.get_patterns();

    let has_iso8601 = patterns
        .iter()
        .any(|p| matches!(p.format_type, TimestampFormat::ISO8601Enhanced));
    assert!(has_iso8601, "Missing ISO8601 patterns");

    let has_unix = patterns
        .iter()
        .any(|p| matches!(p.format_type, TimestampFormat::UnixTimestamp));
    assert!(has_unix, "Missing Unix timestamp patterns");

    let has_k8s = patterns
        .iter()
        .any(|p| matches!(p.format_type, TimestampFormat::KubernetesLog));
    assert!(has_k8s, "Missing Kubernetes patterns");

    let has_us = patterns
        .iter()
        .any(|p| matches!(p.format_type, TimestampFormat::USDate));
    assert!(has_us, "Missing US date patterns");

    let has_db = patterns
        .iter()
        .any(|p| matches!(p.format_type, TimestampFormat::MySQLTimestamp));
    assert!(has_db, "Missing database patterns");
}

#[test]
fn test_priority_ordering_constitutional_requirement() {
    let registry = TimestampRegistry::new();
    let patterns = registry.get_patterns();

    let unix_patterns: Vec<_> = patterns
        .iter()
        .filter(|p| {
            matches!(
                p.format_type,
                TimestampFormat::UnixTimestamp
                    | TimestampFormat::UnixTimestampMs
                    | TimestampFormat::UnixTimestampNs
            )
        })
        .collect();

    assert!(!unix_patterns.is_empty(), "Must have Unix timestamp patterns");

    for pattern in &unix_patterns {
        assert!(
            pattern.priority.unix_timestamp_penalty,
            "Unix timestamp {:?} must have penalty",
            pattern.format_type
        );
    }
}

#[test]
fn test_detect_and_replace_basic_formats() {
    let test_cases = vec![
        ("2025-09-29T10:15:30Z Service started", true),
        ("E0929 13:07:09.181236 3116 error", true),
        ("Jan 29 10:15:30 kernel: USB connected", true),
    ];

    for (input, expect_timestamp) in test_cases {
        let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        if expect_timestamp {
            assert!(
                result.contains("<TIMESTAMP>"),
                "Should detect timestamp in: {input}"
            );
            assert!(!tokens.is_empty(), "Should have tokens for: {input}");
        }
    }
}
