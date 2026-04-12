use lessence::config::Config;
use lessence::normalize::Normalizer;

#[test]
fn test_pattern_detection_unchanged() {
    let config = Config::default();
    let normalizer = Normalizer::new(config);

    let test_cases = vec![
        ("2025-10-06 12:00:00", "<TIMESTAMP>"),
        ("user@example.com", "<EMAIL>"),
        ("192.168.1.1", "<IP>"),
        ("/var/log/system.log", "<PATH>"),
        ("550e8400-e29b-41d4-a716-446655440000", "<UUID>"),
    ];

    for (input, expected_token) in test_cases {
        let result = normalizer.normalize_line(input.to_string()).unwrap();
        assert!(
            result.normalized.contains(expected_token),
            "Pattern detection failed for '{input}': expected '{expected_token}' in '{}'",
            result.normalized
        );
    }
}
