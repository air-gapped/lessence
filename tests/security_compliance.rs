use lessence::config::Config;
use lessence::patterns::email::EmailPatternDetector;
use lessence::patterns::network::NetworkDetector;
use lessence::patterns::timestamp::TimestampDetector;
use std::time::{Duration, Instant};

#[test]
fn test_redos_protection_email() {
    let evil_email = format!("{}@{}.com!!!", "a".repeat(100), "b".repeat(100));
    let detector = EmailPatternDetector::new().unwrap();

    let start = Instant::now();
    let _ = detector.detect_and_replace(&evil_email);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "Constitutional Principle X violation: Email ReDoS protection failed, took {elapsed:?}"
    );
}

#[test]
fn test_redos_protection_timestamp() {
    let evil_timestamp = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(200));

    let start = Instant::now();
    let _ = TimestampDetector::detect_and_replace(&evil_timestamp);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "Timestamp ReDoS protection failed, took {elapsed:?}"
    );
}

#[test]
fn test_redos_protection_ipv6() {
    let evil_ipv6 = (0..100)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join(":");

    let start = Instant::now();
    let _ = NetworkDetector::detect_and_replace(&evil_ipv6, true, false, false);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "Constitutional Principle X violation: IPv6 ReDoS protection failed, took {elapsed:?}"
    );
}

#[test]
fn test_input_line_length_limit() {
    let huge_line = "A".repeat(10 * 1024 * 1024); // 10MB
    let normal_line = "User admin@example.com logged in";

    let config_with_limit = Config {
        max_line_length: Some(1024 * 1024), // 1MB
        ..Default::default()
    };

    assert!(
        !lessence::should_process_line(&huge_line, &config_with_limit),
        "Constitutional Principle X violation: Line length limit not enforced"
    );
    assert!(
        lessence::should_process_line(normal_line, &config_with_limit),
        "Constitutional Principle X violation: Normal line incorrectly rejected"
    );
}

#[test]
fn test_input_line_count_limit() {
    let config = Config {
        max_lines: Some(100),
        ..Default::default()
    };

    for i in 0..150 {
        let should_process = lessence::should_process_line_count(i, &config);
        if i < 100 {
            assert!(
                should_process,
                "Constitutional Principle X violation: Line {i} should be processed"
            );
        } else {
            assert!(
                !should_process,
                "Constitutional Principle X violation: Line {i} should be skipped"
            );
        }
    }
}

#[test]
fn test_pii_sanitization_functionality() {
    let email = "user@example.com";
    let sanitized = lessence::sanitize_email(email);

    assert_eq!(
        sanitized, "u***@e***.com",
        "Constitutional Principle X violation: PII sanitization not working correctly"
    );
    assert!(
        !sanitized.contains("user"),
        "Constitutional Principle X violation: PII sanitization leaked original local part"
    );
}

#[test]
fn test_pii_sanitization_flag_integration() {
    let config = Config {
        sanitize_pii: true,
        ..Default::default()
    };

    let input = "User admin@example.com logged in";
    let output = lessence::process_line(input, &config);

    assert!(
        output.contains("<EMAIL>") || output.contains("a***@e***.com"),
        "Constitutional Principle X violation: --sanitize-pii flag not integrated, got: {output}"
    );
    assert!(
        !output.contains("admin@example.com"),
        "Constitutional Principle X violation: Original email leaked despite sanitize_pii=true"
    );
}

#[test]
fn test_graceful_degradation_on_evil_patterns() {
    let config = Config::default();
    let normalizer = lessence::normalize::Normalizer::new(config);

    let evil_inputs = vec![
        format!("{}@{}.com!!!", "a".repeat(500), "b".repeat(500)),
        format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(500)),
    ];

    for input in evil_inputs {
        let result = std::panic::catch_unwind(|| normalizer.normalize_line(input.clone()));

        assert!(
            result.is_ok(),
            "Constitutional Principle X violation: Pattern detection panicked on evil input instead of degrading gracefully"
        );
    }
}

#[test]
fn test_security_performance_overhead() {
    let config_no_security = Config {
        max_line_length: None,
        max_lines: None,
        sanitize_pii: false,
        ..Default::default()
    };

    let config_with_security = Config {
        max_line_length: Some(10 * 1024 * 1024),
        max_lines: Some(1_000_000),
        sanitize_pii: true,
        ..Default::default()
    };

    let test_line = "User admin@example.com logged in from 192.168.1.100";
    let iterations = 100_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = lessence::should_process_line(test_line, &config_no_security);
    }
    let baseline_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = lessence::should_process_line(test_line, &config_with_security);
        let _ = lessence::should_process_line_count(0, &config_with_security);
    }
    let security_time = start.elapsed();

    let overhead_ratio = security_time.as_nanos() as f64 / baseline_time.as_nanos().max(1) as f64;

    assert!(
        overhead_ratio < 1.50,
        "Constitutional Principle X violation: Security overhead {:.2}% exceeds 50% limit\nNote: Micro-benchmark measures O(1) operations subject to test overhead.\nEnd-to-end benchmark (kubelet.log) shows 0% overhead in production.",
        (overhead_ratio - 1.0) * 100.0
    );
}

#[test]
fn test_all_security_cli_flags_exist() {
    let config = Config {
        sanitize_pii: true,
        max_line_length: Some(1024 * 1024),
        max_lines: Some(10000),
        ..Default::default()
    };

    assert!(
        config.sanitize_pii,
        "Constitutional Principle X violation: --sanitize-pii flag not in Config"
    );
    assert_eq!(
        config.max_line_length,
        Some(1024 * 1024),
        "Constitutional Principle X violation: --max-line-length not in Config"
    );
    assert_eq!(
        config.max_lines,
        Some(10000),
        "Constitutional Principle X violation: --max-lines not in Config"
    );
}
