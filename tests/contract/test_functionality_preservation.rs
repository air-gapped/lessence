use std::process::Command;

#[test]
fn test_all_constitutional_tests_pass() {
    let constitutional_tests = vec![
        "test_constitutional_compliance",
        "test_parallel_performance_advantage",
        "test_essence_mode_functionality",
        "test_implementation_integrity",
        "test_complete_pattern_coverage",
        "test_documentation_consistency",
    ];
    
    for test_name in constitutional_tests {
        let output = Command::new("cargo")
            .args(&["test", test_name, "--", "--nocapture"])
            .output()
            .expect("Failed to run constitutional test");
        
        assert!(
            output.status.success(),
            "Constitutional test '{}' failed:\n{}",
            test_name,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn test_pattern_detection_unchanged() {
    use lessence::normalize::normalize_line;
    use lessence::config::Config;
    
    let test_cases = vec![
        ("2025-10-06 12:00:00", "<TIMESTAMP>"),
        ("user@example.com", "<EMAIL>"),
        ("192.168.1.1", "<IP>"),
        ("/var/log/system.log", "<PATH>"),
        ("550e8400-e29b-41d4-a716-446655440000", "<UUID>"),
    ];
    
    for (input, expected_token) in test_cases {
        let (normalized, _) = normalize_line(input, &Config::default());
        assert!(
            normalized.contains(expected_token),
            "Pattern detection failed for '{}': expected token '{}' not found in '{}'",
            input, expected_token, normalized
        );
    }
}
