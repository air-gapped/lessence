use crate::patterns::Token;
use regex::Regex;
use std::sync::LazyLock;

/// RFC 5322 compliant email regex pattern with ReDoS protection
/// Simplified pattern: uses bounded quantifiers {0,63} and {0,253} per RFC 5322 limits
/// Validation layer (validate_email) provides defense-in-depth for edge cases
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}\b",
    )
    .unwrap()
});

/// Email pattern detector for RFC 5322 compliant email addresses
pub struct EmailPatternDetector {
    regex: Regex,
}

impl EmailPatternDetector {
    /// Create new email pattern detector
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            regex: EMAIL_REGEX.clone(),
        })
    }

    /// Detect and replace email addresses in text
    ///
    /// Returns: (normalized_text, detected_tokens)
    /// Replaces all valid emails with `<EMAIL>` token
    pub fn detect_and_replace(&self, text: &str) -> (String, Vec<Token>) {
        let mut tokens = Vec::new();
        let mut normalized = text.to_string();

        // Find all email matches in reverse order to preserve indices
        let mut matches: Vec<_> = self.regex.find_iter(text).collect();
        matches.reverse();

        for email_match in matches {
            let email = email_match.as_str();

            // Additional validation beyond regex
            if self.validate_email(email) {
                tokens.push(Token::Email(email.to_string()));

                // Replace with token in normalized text
                normalized.replace_range(email_match.range(), "<EMAIL>");
            }
        }

        // Reverse tokens to maintain original order
        tokens.reverse();

        (normalized, tokens)
    }

    /// Validate that a detected string is a proper email address
    ///
    /// Additional validation beyond regex to prevent false positives
    pub fn validate_email(&self, candidate: &str) -> bool {
        // Length check (RFC 5321 limit)
        if candidate.len() > 320 {
            return false;
        }

        // Must contain exactly one @ symbol
        let at_count = candidate.chars().filter(|&c| c == '@').count();
        if at_count != 1 {
            return false;
        }

        // Split into local and domain parts
        let parts: Vec<&str> = candidate.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let local = parts[0];
        let domain = parts[1];

        // Non-empty local and domain parts
        if local.is_empty() || domain.is_empty() {
            return false;
        }

        // Domain must contain at least one dot for TLD
        if !domain.contains('.') {
            return false;
        }

        // Domain cannot start or end with dot
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }

        // Local part cannot start or end with dot
        if local.starts_with('.') || local.ends_with('.') {
            return false;
        }

        true
    }
}

impl Default for EmailPatternDetector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detector_creation() {
        let detector = EmailPatternDetector::new();
        assert!(detector.is_ok(), "Email detector creation should succeed");
    }

    #[test]
    fn test_basic_email_detection() {
        let detector = EmailPatternDetector::new().unwrap();
        let (normalized, tokens) = detector.detect_and_replace("User test@example.com logged in");

        assert_eq!(normalized, "User <EMAIL> logged in");
        assert_eq!(tokens.len(), 1);
        match &tokens[0] {
            Token::Email(email) => assert_eq!(email, "test@example.com"),
            _ => panic!("Expected Email token"),
        }
    }

    #[test]
    fn test_multiple_emails_detection() {
        let detector = EmailPatternDetector::new().unwrap();
        let (normalized, tokens) =
            detector.detect_and_replace("Forward from alice@company.com to bob@company.com");

        assert_eq!(normalized, "Forward from <EMAIL> to <EMAIL>");
        assert_eq!(tokens.len(), 2);

        match &tokens[0] {
            Token::Email(email) => assert_eq!(email, "alice@company.com"),
            _ => panic!("Expected Email token"),
        }
        match &tokens[1] {
            Token::Email(email) => assert_eq!(email, "bob@company.com"),
            _ => panic!("Expected Email token"),
        }
    }

    #[test]
    fn test_no_false_positives() {
        let detector = EmailPatternDetector::new().unwrap();
        let test_cases = vec![
            "@domain.com",       // Missing local part
            "user@",             // Missing domain
            "user@.com",         // Invalid domain
            "not-an-email",      // No @ symbol
            "user@domain@extra", // Multiple @ symbols
            "user@domain",       // No TLD
        ];

        for case in test_cases {
            let (normalized, tokens) = detector.detect_and_replace(case);
            assert_eq!(normalized, case, "Should not modify invalid email: {case}");
            assert_eq!(
                tokens.len(),
                0,
                "Should not detect tokens for invalid email: {case}"
            );
        }
    }

    #[test]
    fn test_email_validation() {
        let detector = EmailPatternDetector::new().unwrap();

        // Valid emails
        assert!(detector.validate_email("user@domain.com"));
        assert!(detector.validate_email("first.last@subdomain.example.org"));
        assert!(detector.validate_email("admin+tag@company-name.co.uk"));

        // Invalid emails
        assert!(!detector.validate_email(""));
        assert!(!detector.validate_email(&"a".repeat(321))); // Too long
        assert!(!detector.validate_email("user@domain@extra")); // Multiple @
        assert!(!detector.validate_email("@domain.com")); // Missing local
        assert!(!detector.validate_email("user@")); // Missing domain
        assert!(!detector.validate_email("user@.com")); // Invalid domain start
        assert!(!detector.validate_email("user@domain.")); // Invalid domain end
        assert!(!detector.validate_email(".user@domain.com")); // Invalid local start
        assert!(!detector.validate_email("user.@domain.com")); // Invalid local end
        assert!(!detector.validate_email("user@domain")); // No TLD
    }

    #[test]
    fn test_complex_email_formats() {
        let detector = EmailPatternDetector::new().unwrap();

        let test_cases = vec![
            ("user@example.com", true),
            ("first.last@domain.co.uk", true),
            ("admin+tag@company.org", true),
            ("test_user@sub.domain.com", true),
            ("user123@domain123.net", true),
            ("user-name@domain-name.info", true),
        ];

        for (email, should_detect) in test_cases {
            let (normalized, tokens) = detector.detect_and_replace(&format!("Email: {email}"));

            if should_detect {
                assert_eq!(normalized, "Email: <EMAIL>");
                assert_eq!(tokens.len(), 1);
                match &tokens[0] {
                    Token::Email(detected) => assert_eq!(detected, email),
                    _ => panic!("Expected Email token for: {email}"),
                }
            } else {
                assert_eq!(normalized, format!("Email: {email}"));
                assert_eq!(tokens.len(), 0);
            }
        }
    }

    // ---- validate_email: boundary tests ----

    #[test]
    fn validate_email_exactly_320_chars() {
        let local = "a".repeat(63);
        let domain = format!("{}.com", "b".repeat(250));
        let email = format!("{local}@{domain}");
        assert!(email.len() <= 320);
        let detector = EmailPatternDetector::new().unwrap();
        assert!(detector.validate_email(&email));
    }

    #[test]
    fn validate_email_321_chars_rejected() {
        // Build a 321-char email: local@domain
        let local = "a".repeat(64);
        let domain_body = "b".repeat(321 - 64 - 1 - 4); // -local -@ -.com
        let email = format!("{local}@{domain_body}.com");
        assert!(
            email.len() > 320,
            "email len {} should exceed 320",
            email.len()
        );
        let detector = EmailPatternDetector::new().unwrap();
        assert!(!detector.validate_email(&email));
    }

    // ---- Mutant-killing: validate_email boundary > vs >= on length 320 ----

    #[test]
    fn validate_email_exactly_320_accepted() {
        // Kills mutant: `> 320` → `>= 320` (line 63)
        // Build exactly 320 chars
        let local = "a".repeat(50);
        let domain_needed = 320 - 50 - 1 - 4; // 265 chars for domain body
        let domain_body = "b".repeat(domain_needed);
        let email = format!("{local}@{domain_body}.com");
        assert_eq!(email.len(), 320, "email len should be exactly 320");
        let detector = EmailPatternDetector::new().unwrap();
        assert!(
            detector.validate_email(&email),
            "320-char email should be accepted"
        );
    }

    #[test]
    fn validate_email_exactly_321_rejected() {
        let local = "a".repeat(50);
        let domain_needed = 321 - 50 - 1 - 4; // 266 chars
        let domain_body = "b".repeat(domain_needed);
        let email = format!("{local}@{domain_body}.com");
        assert_eq!(email.len(), 321, "email len should be exactly 321");
        let detector = EmailPatternDetector::new().unwrap();
        assert!(
            !detector.validate_email(&email),
            "321-char email should be rejected"
        );
    }
}
