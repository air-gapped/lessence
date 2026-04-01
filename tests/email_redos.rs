// Contract Test: Email Pattern ReDoS Resistance
// This test MUST FAIL initially, then PASS after email pattern simplification

use std::time::{Duration, Instant};

#[test]
fn test_email_redos_resistance_50_chars() {
    // Given: Malicious email pattern with 50 repeating chars and invalid ending
    let evil_email = format!("{}@{}.com!!!", "a".repeat(50), "b".repeat(50));

    // When: Email pattern detector processes the malicious input
    let detector = lessence::patterns::email::EmailPatternDetector::new().unwrap();
    let start = Instant::now();
    let (_normalized, _tokens) = detector.detect_and_replace(&evil_email);
    let elapsed = start.elapsed();

    // Then: Processing completes in <100ms (ReDoS protection requirement)
    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: email pattern took {:?} for input length {}",
        elapsed,
        evil_email.len()
    );
}

#[test]
fn test_email_redos_resistance_100_chars() {
    // Given: Larger malicious pattern (100 chars)
    let evil_email = format!("{}@{}.com!!!", "a".repeat(100), "b".repeat(100));

    // When: Processing the larger evil pattern
    let detector = lessence::patterns::email::EmailPatternDetector::new().unwrap();
    let start = Instant::now();
    let (_normalized, _tokens) = detector.detect_and_replace(&evil_email);
    let elapsed = start.elapsed();

    // Then: Still completes in <100ms despite larger input
    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected on large input: took {:?} for {} chars",
        elapsed,
        evil_email.len()
    );
}

#[test]
fn test_email_multiple_evil_patterns_same_line() {
    // Given: Multiple evil patterns in one line
    let evil_line = format!(
        "User {}@{}.com!!! and {}@{}.org!!! attempted login",
        "a".repeat(50),
        "b".repeat(50),
        "x".repeat(50),
        "y".repeat(50)
    );

    // When: Processing line with multiple evil patterns
    let detector = lessence::patterns::email::EmailPatternDetector::new().unwrap();
    let start = Instant::now();
    let (_normalized, _tokens) = detector.detect_and_replace(&evil_line);
    let elapsed = start.elapsed();

    // Then: Completes in <200ms (100ms per pattern)
    assert!(
        elapsed < Duration::from_millis(200),
        "Multiple evil patterns took {elapsed:?}"
    );
}

#[test]
fn test_email_valid_emails_still_detected() {
    // Given: Valid email addresses (regression check)
    let valid_emails = vec![
        "user@example.com",
        "first.last@company.org",
        "admin+tag@subdomain.example.co.uk",
        "a@b.co",
    ];

    let detector = lessence::patterns::email::EmailPatternDetector::new().unwrap();

    // When/Then: All valid emails still detected after pattern change
    for email in valid_emails {
        let input = format!("Email: {email}");
        let (normalized, tokens) = detector.detect_and_replace(&input);

        assert_eq!(normalized, "Email: <EMAIL>", "Failed to detect: {email}");
        assert_eq!(tokens.len(), 1, "Wrong token count for: {email}");
    }
}

#[test]
fn test_email_leading_trailing_dots_still_rejected() {
    // Given: Invalid emails with leading/trailing dots
    let invalid_emails = vec![
        ".user@domain.com", // Leading dot in local part
        "user.@domain.com", // Trailing dot in local part
        "user@.domain.com", // Leading dot in domain
        "user@domain.com.", // Trailing dot in domain
    ];

    let detector = lessence::patterns::email::EmailPatternDetector::new().unwrap();

    // When/Then: Validation layer still rejects these (defense-in-depth)
    for email in invalid_emails {
        let is_valid = detector.validate_email(email);
        assert!(!is_valid, "Should reject invalid email: {email}");
    }
}
