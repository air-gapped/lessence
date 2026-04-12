// Contract Test: Email Pattern ReDoS Resistance
//
// Tests that email pattern detection scales linearly with input size.
// Uses scaling-ratio approach: 4x input should take ~4x time, not 16x.

use lessence::patterns::email::EmailPatternDetector;

#[test]
fn test_email_redos_long_local_part_scales_linearly() {
    let small = format!("{}@{}.com!!!", "a".repeat(25), "b".repeat(25));
    let large = format!("{}@{}.com!!!", "a".repeat(100), "b".repeat(100));

    crate::common::assert_linear_scaling("long_local_part", &small, &large, |input| {
        let detector = EmailPatternDetector::new().unwrap();
        let _ = detector.detect_and_replace(input);
    });
}

#[test]
fn test_email_redos_multiple_evil_patterns_scales_linearly() {
    let small = (0..2)
        .map(|i| {
            format!(
                "{}@{}.com!!!",
                "a".repeat(25),
                char::from(b'a' + (i % 26) as u8).to_string().repeat(25)
            )
        })
        .collect::<Vec<_>>()
        .join(" and ");
    let large = (0..8)
        .map(|i| {
            format!(
                "{}@{}.com!!!",
                "a".repeat(25),
                char::from(b'a' + (i % 26) as u8).to_string().repeat(25)
            )
        })
        .collect::<Vec<_>>()
        .join(" and ");

    crate::common::assert_linear_scaling("multiple_evil", &small, &large, |input| {
        let detector = EmailPatternDetector::new().unwrap();
        let _ = detector.detect_and_replace(input);
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
