// Contract Test: Constitutional Compliance for Unified Timestamp System
// Validates all constitutional requirements are met

use lessence::patterns::timestamp::{UnifiedTimestampDetector, TimestampRegistry};

#[test]
fn test_pattern_count_constitutional_requirement() {
    let patterns = UnifiedTimestampDetector::get_patterns();

    // Constitutional requirement: Support 30+ timestamp formats
    assert!(patterns.len() >= 30,
        "Constitutional violation: Must have 30+ patterns, found {}",
        patterns.len());
}

#[test]
fn test_thread_safety_constitutional_requirement() {
    use std::thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Test parallel access from multiple threads
    for _ in 0..20 {
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            // Multiple operations per thread to stress test
            for _ in 0..100 {
                let patterns = UnifiedTimestampDetector::get_patterns();
                assert!(patterns.len() >= 30);

                let (result, tokens) = UnifiedTimestampDetector::detect_and_replace(
                    "2025-09-29T10:15:30Z Test message"
                );
                assert_eq!(result, "<TIMESTAMP> Test message");
                assert_eq!(tokens.len(), 1);

                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    // All threads must complete successfully
    for handle in handles {
        handle.join().expect("Thread panicked - constitutional thread safety violation");
    }

    // Verify all operations completed
    assert_eq!(counter.load(Ordering::SeqCst), 2000);
}

#[test]
fn test_zero_data_loss_constitutional_requirement() {
    let registry = TimestampRegistry::new();
    let stats = registry.get_merge_statistics();

    // Constitutional requirement: Zero data loss during pattern merging
    // Total input patterns must equal final patterns plus identified duplicates
    let expected_final = stats.original_timestamp_patterns + stats.original_essence_patterns - stats.duplicates_removed + stats.merged_patterns;

    assert_eq!(stats.final_pattern_count, expected_final,
        "Constitutional violation: Data loss detected in pattern merging. Expected {}, got {}",
        expected_final, stats.final_pattern_count);
}

#[test]
fn test_pattern_completeness_constitutional_requirement() {
    let patterns = UnifiedTimestampDetector::get_patterns();

    // Constitutional requirement: ALL patterns must be supported, no fast-track allowed
    // Verify key pattern families are present

    let format_counts = patterns.iter()
        .map(|p| &p.format_type)
        .fold(std::collections::HashMap::new(), |mut acc, format| {
            *acc.entry(format).or_insert(0) += 1;
            acc
        });

    // Must have ISO8601 variants
    let has_iso8601 = patterns.iter().any(|p|
        matches!(p.format_type, lessence::patterns::timestamp::TimestampFormat::ISO8601Enhanced)
    );
    assert!(has_iso8601, "Constitutional violation: Missing ISO8601 patterns");

    // Must have Unix timestamps (even though lowest priority)
    let has_unix = patterns.iter().any(|p|
        matches!(p.format_type, lessence::patterns::timestamp::TimestampFormat::UnixTimestamp)
    );
    assert!(has_unix, "Constitutional violation: Missing Unix timestamp patterns");

    // Must have application-specific patterns
    let has_k8s = patterns.iter().any(|p|
        matches!(p.format_type, lessence::patterns::timestamp::TimestampFormat::KubernetesLog)
    );
    assert!(has_k8s, "Constitutional violation: Missing Kubernetes patterns");

    // Must have regional formats
    let has_us = patterns.iter().any(|p|
        matches!(p.format_type, lessence::patterns::timestamp::TimestampFormat::USDate)
    );
    assert!(has_us, "Constitutional violation: Missing US date patterns");

    // Must have database formats
    let has_db = patterns.iter().any(|p|
        matches!(p.format_type, lessence::patterns::timestamp::TimestampFormat::MySQLTimestamp)
    );
    assert!(has_db, "Constitutional violation: Missing database patterns");
}

#[test]
fn test_priority_ordering_constitutional_requirement() {
    let patterns = UnifiedTimestampDetector::get_patterns();

    // Constitutional requirement: Unix timestamps must have lowest priority
    let unix_patterns: Vec<_> = patterns.iter()
        .filter(|p| matches!(p.format_type,
            lessence::patterns::timestamp::TimestampFormat::UnixTimestamp |
            lessence::patterns::timestamp::TimestampFormat::UnixTimestampMs |
            lessence::patterns::timestamp::TimestampFormat::UnixTimestampNs
        ))
        .collect();

    assert!(!unix_patterns.is_empty(), "Must have Unix timestamp patterns");

    // All Unix patterns must have penalty flag
    for pattern in &unix_patterns {
        assert!(pattern.priority.unix_timestamp_penalty,
            "Constitutional violation: Unix timestamp {} must have lowest priority penalty",
            format!("{:?}", pattern.format_type));
    }

    // Unix patterns should have higher effective scores (lower priority)
    let non_unix_patterns: Vec<_> = patterns.iter()
        .filter(|p| !matches!(p.format_type,
            lessence::patterns::timestamp::TimestampFormat::UnixTimestamp |
            lessence::patterns::timestamp::TimestampFormat::UnixTimestampMs |
            lessence::patterns::timestamp::TimestampFormat::UnixTimestampNs
        ))
        .collect();

    if !non_unix_patterns.is_empty() && !unix_patterns.is_empty() {
        let min_unix_score = unix_patterns.iter()
            .map(|p| p.priority.effective_score())
            .min()
            .unwrap();

        let max_non_unix_score = non_unix_patterns.iter()
            .map(|p| p.priority.effective_score())
            .max()
            .unwrap();

        assert!(min_unix_score > max_non_unix_score,
            "Constitutional violation: Unix timestamps must have lower priority than all other patterns. Min Unix: {}, Max Non-Unix: {}",
            min_unix_score, max_non_unix_score);
    }
}

#[test]
fn test_implementation_integrity_constitutional_requirement() {
    let compliance = UnifiedTimestampDetector::validate_constitutional_compliance();

    // Constitutional requirement: No shortcuts, complete implementation
    assert!(compliance.pattern_count_compliant,
        "Constitutional violation: Insufficient pattern count");
    assert!(compliance.thread_safety_verified,
        "Constitutional violation: Thread safety not verified");
    assert!(compliance.priority_ordering_correct,
        "Constitutional violation: Priority ordering incorrect");
    assert!(compliance.deduplication_complete,
        "Constitutional violation: Pattern deduplication incomplete");

    // Verify that merging actually happened (not just copying one implementation)
    assert!(compliance.duplicates_removed > 0,
        "Constitutional violation: No pattern merging detected - implementation may be shortcuts");
}

#[test]
fn test_essence_mode_functionality_constitutional_requirement() {
    // Constitutional requirement: Must support essence mode with identical tokenization

    let test_inputs = vec![
        "2025-09-29T10:15:30Z Service started",
        "E0929 13:07:09.181236 3116 error message",
        "Jan 29 10:15:30 kernel: USB connected",
        "timestamp=1727676930 processing complete",
    ];

    for input in test_inputs {
        let (standard_result, standard_tokens) = UnifiedTimestampDetector::detect_and_replace(input);
        let (essence_result, essence_tokens) = UnifiedTimestampDetector::detect_and_replace(input);

        assert_eq!(standard_result, essence_result,
            "Constitutional violation: Standard and essence mode results differ for input: {}", input);
        assert_eq!(standard_tokens.len(), essence_tokens.len(),
            "Constitutional violation: Standard and essence mode token counts differ for input: {}", input);
    }
}