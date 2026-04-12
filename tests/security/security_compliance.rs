// Security Compliance Tests
//
// ReDoS tests use scaling-ratio approach (4x input should take ~4x time).
// Non-timing security tests (input limits, PII) use direct assertions.

use lessence::config::Config;
use lessence::patterns::email::EmailPatternDetector;
use lessence::patterns::network::NetworkDetector;
use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_redos_protection_email() {
    let small = format!("{}@{}.com!!!", "a".repeat(25), "b".repeat(25));
    let large = format!("{}@{}.com!!!", "a".repeat(100), "b".repeat(100));

    crate::common::assert_linear_scaling("email_redos", &small, &large, |input| {
        let detector = EmailPatternDetector::new().unwrap();
        let _ = detector.detect_and_replace(input);
    });
}

#[test]
fn test_redos_protection_timestamp() {
    let small = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(50));
    let large = format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(200));

    crate::common::assert_linear_scaling("timestamp_redos", &small, &large, |input| {
        let _ = TimestampDetector::detect_and_replace(input);
    });
}

#[test]
fn test_redos_protection_ipv6() {
    let small = (0..25)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join(":");
    let large = (0..100)
        .map(|i| format!("{:x}", i % 16))
        .collect::<Vec<_>>()
        .join(":");

    crate::common::assert_linear_scaling("ipv6_redos", &small, &large, |input| {
        let _ = NetworkDetector::detect_and_replace(input, true, false, false);
    });
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
        "Should reject line exceeding max_line_length"
    );
    assert!(
        lessence::should_process_line(normal_line, &config_with_limit),
        "Should accept normal-length line"
    );
}

#[test]
fn test_input_line_count_limit() {
    let config_with_limit = Config {
        max_lines: Some(100),
        ..Default::default()
    };

    assert!(
        lessence::should_process_line_count(50, &config_with_limit),
        "Should process line within limit"
    );
    assert!(
        !lessence::should_process_line_count(150, &config_with_limit),
        "Should reject line exceeding max_lines"
    );
}

#[test]
fn test_pii_sanitization_functionality() {
    use lessence::sanitize_email;
    let masked = sanitize_email("user@example.com");
    assert!(
        !masked.contains("user@example.com"),
        "Email should be masked, got: {masked}"
    );
    // sanitize_email masks to "u***@e***.com" format, not <EMAIL>
    assert!(
        masked.contains("***"),
        "Should contain masked portion, got: {masked}"
    );
}

#[test]
fn test_all_security_cli_flags_exist() {
    use std::process::Command;
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--help")
        .output()
        .expect("Failed to run lessence");

    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("sanitize-pii"),
        "Should have --sanitize-pii flag"
    );
    assert!(
        help.contains("max-line-length"),
        "Should have --max-line-length flag"
    );
    assert!(help.contains("max-lines"), "Should have --max-lines flag");
}

#[test]
fn test_pii_sanitization_flag_integration() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--sanitize-pii", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"User admin@company.com logged in\n")
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("admin@company.com"),
        "Email should be masked with --sanitize-pii"
    );
}

#[test]
fn test_security_performance_overhead() {
    // Security features (sanitize_pii, max_line_length) must scale linearly.
    fn make_input(multiplier: usize) -> String {
        let count = 10 * multiplier;
        (0..count)
            .map(|i| {
                format!(
                    "2025-01-20 10:15:{:02} User user{}@example.com from 192.168.1.{}",
                    i % 60,
                    i,
                    i % 256
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    let config = Config {
        sanitize_pii: true,
        max_line_length: Some(1024 * 1024),
        max_lines: Some(1_000_000),
        ..Default::default()
    };

    let small = make_input(1);
    let large = make_input(4);
    let normalizer = lessence::normalize::Normalizer::new(config);

    crate::common::assert_linear_scaling("security_overhead", &small, &large, |input| {
        for line in input.lines() {
            let _ = normalizer.normalize_line(line.to_string());
        }
    });
}

#[test]
fn test_graceful_degradation_on_evil_patterns() {
    // Evil inputs should produce SOME output, not crash
    let evil_inputs = vec![
        format!("{}@{}.com", "a".repeat(1000), "b".repeat(1000)),
        format!("2024{}", "-01".repeat(100)),
        "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f::x".to_string(),
    ];

    let config = Config::default();
    let normalizer = lessence::normalize::Normalizer::new(config);

    for input in evil_inputs {
        let result = normalizer.normalize_line(input.clone());
        assert!(
            result.is_ok(),
            "Should not fail on evil input: {}...",
            &input[..input.len().min(50)]
        );
    }
}
