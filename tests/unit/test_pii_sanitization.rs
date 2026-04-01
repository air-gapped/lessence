use lessence::patterns::Token;
use lessence::apply_pii_masking;

#[cfg(test)]
mod pii_masking_tests {
    use super::*;
    
    #[test]
    fn test_single_email_masking() {
        let original = "User alice@example.com logged in";
        let tokens = vec![Token::Email("alice@example.com".to_string())];
        
        let masked = apply_pii_masking(original, &tokens);
        
        assert_eq!(masked, "User <EMAIL> logged in");
        assert!(!masked.contains("alice@example.com"), "Email should be masked");
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
        // Count occurrences of <EMAIL>
        assert_eq!(masked.matches("<EMAIL>").count(), 2);
        assert!(!masked.contains("alice@ex.com"));
    }

    #[test]
    fn test_no_emails_unchanged() {
        let original = "ERROR: Connection timeout";
        let tokens = vec![];  // No email tokens
        
        let masked = apply_pii_masking(original, &tokens);
        
        assert_eq!(masked, original, "Should be unchanged when no emails");
    }

    #[test]
    fn test_malformed_emails_unchanged() {
        // EmailPatternDetector.validate_email() rejects these
        let original = "Contact: user@domain (no TLD) or @example.com (no local)";
        let tokens = vec![];  // Malformed emails not detected
        
        let masked = apply_pii_masking(original, &tokens);
        
        assert_eq!(masked, original, "Malformed emails should be unchanged");
    }
}
