// Contract Test: Email Pattern ReDoS Resistance
//
// Tests that email pattern detection scales linearly with input size.
// Uses scaling-ratio approach: 4x input should take ~4x time, not 16x.

use lessence::patterns::email::EmailPatternDetector;
use std::time::Instant;

fn measure_email_detect(input: &str, iterations: u32) -> std::time::Duration {
    let detector = EmailPatternDetector::new().unwrap();
    for _ in 0..iterations / 10 {
        let _ = detector.detect_and_replace(input);
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = detector.detect_and_replace(input);
    }
    start.elapsed()
}

fn assert_linear_scaling(label: &str, make_input: impl Fn(usize) -> String) {
    let small = make_input(1);
    let large = make_input(4);
    let iters = 500;

    let time_small = measure_email_detect(&small, iters);
    let time_large = measure_email_detect(&large, iters);

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;

    assert!(
        ratio < 8.0,
        "{label}: scaling ratio {ratio:.1}x for 4x input (expected <8.0). \
         small={small_ns}ns, large={large_ns}ns",
        small_ns = time_small.as_nanos() / u128::from(iters),
        large_ns = time_large.as_nanos() / u128::from(iters),
    );
}

#[test]
fn test_email_redos_long_local_part_scales_linearly() {
    assert_linear_scaling("long_local_part", |multiplier| {
        let len = 25 * multiplier;
        format!("{}@{}.com!!!", "a".repeat(len), "b".repeat(len))
    });
}

#[test]
fn test_email_redos_multiple_evil_patterns_scales_linearly() {
    assert_linear_scaling("multiple_evil", |multiplier| {
        let count = 2 * multiplier;
        (0..count)
            .map(|i| {
                format!(
                    "{}@{}.com!!!",
                    "a".repeat(25),
                    char::from(b'a' + (i % 26) as u8).to_string().repeat(25)
                )
            })
            .collect::<Vec<_>>()
            .join(" and ")
    });
}

#[test]
fn test_email_valid_emails_still_detected() {
    let valid_emails = vec![
        "user@example.com",
        "first.last@company.org",
        "admin+tag@subdomain.example.co.uk",
        "a@b.co",
    ];

    let detector = EmailPatternDetector::new().unwrap();

    for email in valid_emails {
        let input = format!("Email: {email}");
        let (normalized, tokens) = detector.detect_and_replace(&input);
        assert_eq!(normalized, "Email: <EMAIL>", "Failed to detect: {email}");
        assert_eq!(tokens.len(), 1, "Wrong token count for: {email}");
    }
}

#[test]
fn test_email_leading_trailing_dots_still_rejected() {
    let invalid_emails = vec![
        ".user@domain.com",
        "user.@domain.com",
        "user@.domain.com",
        "user@domain.com.",
    ];

    let detector = EmailPatternDetector::new().unwrap();

    for email in invalid_emails {
        let is_valid = detector.validate_email(email);
        assert!(!is_valid, "Should reject invalid email: {email}");
    }
}
