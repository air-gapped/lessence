use lessence::apply_pii_masking;
use lessence::patterns::Token;

#[cfg(test)]
mod pii_masking_tests {
    use super::*;

    #[test]
    fn test_single_email_masking() {
        let original = "User alice@example.com logged in";
        let tokens = vec![Token::Email("alice@example.com".to_string())];

        let masked = apply_pii_masking(original, &tokens);

        assert_eq!(masked, "User <EMAIL> logged in");
        assert!(
            !masked.contains("alice@example.com"),
            "Email should be masked"
        );
        assert!(!masked.contains('@'), "No @ symbol should remain");
    }

    #[test]
    fn test_multiple_emails_masking() {
        let original = "Forward from alice@ex.com to bob@ex.com";
        let tokens = vec![
            Token::Email("alice@ex.com".to_string()),
            Token::Email("bob@ex.com".to_string()),
        ];

        let masked = apply_pii_masking(original, &tokens);

        assert_eq!(masked, "Forward from <EMAIL> to <EMAIL>");
        assert!(!masked.contains("alice@ex.com"));
        assert!(!masked.contains("bob@ex.com"));
    }

    #[test]
    fn test_duplicate_email_masking() {
        let original = "Reply-To: alice@ex.com (alice@ex.com)";
        let tokens = vec![Token::Email("alice@ex.com".to_string())];

        let masked = apply_pii_masking(original, &tokens);

        assert_eq!(masked, "Reply-To: <EMAIL> (<EMAIL>)");
        assert_eq!(masked.matches("<EMAIL>").count(), 2);
        assert!(!masked.contains("alice@ex.com"));
    }

    #[test]
    fn test_no_emails_unchanged() {
        let original = "ERROR: Connection timeout";
        let no_email_tokens = vec![];

        let masked = apply_pii_masking(original, &no_email_tokens);

        assert_eq!(masked, original, "Should be unchanged when no emails");
    }

    #[test]
    fn test_malformed_emails_unchanged() {
        let original = "Contact: user@domain (no TLD) or @example.com (no local)";
        let tokens_validate_email_rejects_malformed = vec![];

        let masked = apply_pii_masking(original, &tokens_validate_email_rejects_malformed);

        assert_eq!(masked, original, "Malformed emails should be unchanged");
    }
}
