// Contract Test: Constitutional Compliance for Unified Timestamp System

use lessence::patterns::timestamp::{UnifiedTimestampDetector, patterns};

#[test]
fn test_pattern_count_constitutional_requirement() {
    assert!(
        patterns().len() >= 30,
        "Constitutional violation: Must have 30+ patterns, found {}",
        patterns().len()
    );
}

#[test]
fn test_thread_safety_constitutional_requirement() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        handle
            .join()
            .expect("Thread panicked — thread safety violation");
    }

    assert_eq!(counter.load(Ordering::SeqCst), 2000);
}

#[test]
fn test_pattern_completeness_constitutional_requirement() {
    // One representative per family must be present. Names are the stable
    // identifiers in the pattern table.
    for required in [
        "iso8601-enhanced",
        "unix-timestamp",
        "kubernetes-log",
        "us-date",
        "mysql-timestamp",
    ] {
        assert!(
            patterns().iter().any(|p| p.name == required),
            "Missing pattern: {required}"
        );
    }
}

#[test]
fn test_priority_ordering_constitutional_requirement() {
    // Unix epoch patterns must lose every overlap against a real date: a bare
    // 10-13 digit integer is far more often an id, a size, or a port.
    let unix: Vec<i32> = patterns()
        .iter()
        .filter(|p| p.name.starts_with("unix-"))
        .map(|p| p.score)
        .collect();
    assert!(!unix.is_empty(), "Must have Unix timestamp patterns");

    let worst_other = patterns()
        .iter()
        .filter(|p| !p.name.starts_with("unix-"))
        .map(|p| p.score)
        .max()
        .expect("table has non-unix patterns");

    for score in unix {
        assert!(
            score > worst_other,
            "Unix pattern scored {score}, must rank below every other pattern ({worst_other})"
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
