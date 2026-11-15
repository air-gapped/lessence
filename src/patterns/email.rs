use crate::patterns::Token;
use regex::Regex;
use std::sync::LazyLock;

const LOCAL_PART_MAX: usize = 64;
const DOMAIN_MAX: usize = 255;
const DNS_NAME_MAX: usize = 253;
const MAX_ADDRESS_LEN: usize = LOCAL_PART_MAX + "@".len() + DOMAIN_MAX;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let local_tail = LOCAL_PART_MAX - 1;
    Regex::new(&format!(
        r"\b[a-zA-Z0-9][a-zA-Z0-9._+-]{{0,{local_tail}}}@[a-zA-Z0-9][a-zA-Z0-9.-]{{0,{DNS_NAME_MAX}}}\.[a-zA-Z]{{2,}}\b"
    ))
    .unwrap()
});

pub struct EmailPatternDetector {
    regex: Regex,
}

impl EmailPatternDetector {
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            regex: EMAIL_REGEX.clone(),
        })
    }

    pub fn detect_and_replace(&self, text: &str) -> (String, Vec<Token>) {
        let mut tokens = Vec::new();
        let normalized = self
            .regex
            .replace_all(text, |caps: &regex::Captures| {
                let email = &caps[0];
                if self.validate_email(email) {
                    tokens.push(Token::Email(email.to_string()));
                    "<EMAIL>".to_string()
                } else {
                    email.to_string()
                }
            })
            .into_owned();
        (normalized, tokens)
    }

    pub fn validate_email(&self, candidate: &str) -> bool {
        if candidate.len() > MAX_ADDRESS_LEN {
            return false;
        }

        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        if domain.contains('@') {
            return false;
        }

        if Self::is_systemd_unit_name(domain) {
            return false;
        }

        if local.is_empty() || domain.is_empty() {
            return false;
        }

        if !domain.contains('.') {
            return false;
        }

        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }

        if local.starts_with('.') || local.ends_with('.') {
            return false;
        }

        true
    }

    fn is_systemd_unit_name(domain: &str) -> bool {
        domain
            .rsplit('.')
            .next()
            .is_some_and(super::is_systemd_unit_type)
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
        for (case, reason) in [
            ("@domain.com", "missing local part"),
            ("user@", "missing domain"),
            ("user@.com", "domain starts with a dot"),
            ("not-an-email", "no @"),
            ("user@domain@extra", "two @"),
            ("user@domain", "no TLD"),
        ] {
            let (normalized, tokens) = detector.detect_and_replace(case);
            assert_eq!(normalized, case, "{reason}: {case}");
            assert_eq!(tokens.len(), 0, "{reason}: {case}");
        }
    }

    #[test]
    fn test_email_validation() {
        let detector = EmailPatternDetector::new().unwrap();

        assert!(detector.validate_email("user@domain.com"));
        assert!(detector.validate_email("first.last@subdomain.example.org"));
        assert!(detector.validate_email("admin+tag@company-name.co.uk"));

        let too_long = "a".repeat(MAX_ADDRESS_LEN + 1);
        for (candidate, reason) in [
            ("", "empty"),
            (too_long.as_str(), "too long"),
            ("user@domain@extra", "two @"),
            ("@domain.com", "missing local part"),
            ("user@", "missing domain"),
            ("user@.com", "dot at domain start"),
            ("user@domain.", "dot at domain end"),
            (".user@domain.com", "dot at local start"),
            ("user.@domain.com", "dot at local end"),
            ("user@domain", "no TLD"),
        ] {
            assert!(!detector.validate_email(candidate), "{reason}: {candidate}");
        }
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

    #[test]
    fn the_address_length_limit_is_320() {
        assert_eq!(MAX_ADDRESS_LEN, 320);
        let detector = EmailPatternDetector::new().unwrap();
        let tld = ".com";
        for (name, local_len, total_len, accepted) in [
            ("63-char local, 318 in all", 63, 318, true),
            (
                "64-char local, one over the limit",
                64,
                MAX_ADDRESS_LEN + 1,
                false,
            ),
            ("exactly at the limit", 50, MAX_ADDRESS_LEN, true),
            ("one over the limit", 50, MAX_ADDRESS_LEN + 1, false),
        ] {
            let domain_body = "b".repeat(total_len - local_len - "@".len() - tld.len());
            let email = format!("{}@{domain_body}{tld}", "a".repeat(local_len));
            assert_eq!(email.len(), total_len, "{name}");
            assert_eq!(detector.validate_email(&email), accepted, "{name}");
        }
    }

    #[test]
    fn systemd_instance_unit_is_not_an_email() {
        let d = EmailPatternDetector::new().unwrap();
        let (r, t) =
            d.detect_and_replace("modprobe@configfs.service: Deactivated; mail root@example.com");
        assert_eq!(r, "modprobe@configfs.service: Deactivated; mail <EMAIL>");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn every_systemd_unit_type_is_a_unit_not_a_mailbox() {
        let d = EmailPatternDetector::new().unwrap();
        for unit in super::super::SYSTEMD_UNIT_TYPES {
            let line = format!("unit proc-fs@nfsd.{unit} done");
            let (r, t) = d.detect_and_replace(&line);
            assert_eq!(r, line, "{unit}");
            assert!(t.is_empty(), "{unit}: {t:?}");
        }
        assert!(!d.validate_email("systemd-fsck@dev-sda1.automount"));
    }
}
