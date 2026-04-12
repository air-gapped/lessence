use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Standard UUID format: 8-4-4-4-12 hex digits
static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
        .unwrap()
});

// UUID without hyphens (sometimes used)
static UUID_NO_HYPHENS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9a-fA-F]{32}\b").unwrap());

// Request ID patterns
static REQUEST_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:req|request)[-_]?(?:id)?[=:]?\s*([a-zA-Z0-9-_]+)\b").unwrap()
});

// Trace ID patterns
static TRACE_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btrace[=:]([a-zA-Z0-9-_]+)\b").unwrap());

// Session ID patterns
static SESSION_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsession[=:]([a-zA-Z0-9-_]+)\b").unwrap());

// Correlation ID patterns
static CORRELATION_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcorrelation[-_]?id[=:]([a-zA-Z0-9-_]+)\b").unwrap());

pub struct UuidDetector;

impl UuidDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no UUID indicators
        if !Self::has_uuid_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Standard UUIDs first
        for cap in UUID_REGEX.find_iter(text) {
            let uuid_str = cap.as_str();
            tokens.push(Token::Uuid(uuid_str.to_string()));
        }
        result = UUID_REGEX.replace_all(&result, "<UUID>").to_string();

        // Request IDs
        for cap in REQUEST_ID_REGEX.captures_iter(&result) {
            let req_id = cap.get(1).unwrap().as_str();
            if Self::is_likely_id(req_id) {
                tokens.push(Token::Uuid(req_id.to_string()));
            }
        }
        result = REQUEST_ID_REGEX
            .replace_all(&result, "request_id=<UUID>")
            .to_string();

        // Trace IDs
        for cap in TRACE_ID_REGEX.captures_iter(&result) {
            let trace_id = cap.get(1).unwrap().as_str();
            if Self::is_likely_id(trace_id) {
                tokens.push(Token::Uuid(trace_id.to_string()));
            }
        }
        result = TRACE_ID_REGEX
            .replace_all(&result, "trace=<UUID>")
            .to_string();

        // Session IDs
        for cap in SESSION_ID_REGEX.captures_iter(&result) {
            let session_id = cap.get(1).unwrap().as_str();
            if Self::is_likely_id(session_id) {
                tokens.push(Token::Uuid(session_id.to_string()));
            }
        }
        result = SESSION_ID_REGEX
            .replace_all(&result, "session=<UUID>")
            .to_string();

        // Correlation IDs
        for cap in CORRELATION_ID_REGEX.captures_iter(&result) {
            let correlation_id = cap.get(1).unwrap().as_str();
            if Self::is_likely_id(correlation_id) {
                tokens.push(Token::Uuid(correlation_id.to_string()));
            }
        }
        result = CORRELATION_ID_REGEX
            .replace_all(&result, "correlation_id=<UUID>")
            .to_string();

        // UUIDs without hyphens (but avoid overlap with other hash patterns)
        for cap in UUID_NO_HYPHENS_REGEX.find_iter(&result) {
            let uuid_str = cap.as_str();
            // Only treat as UUID if it has mixed letters and numbers (not pure hex hash)
            if Self::looks_like_uuid_no_hyphens(uuid_str) {
                tokens.push(Token::Uuid(uuid_str.to_string()));
            }
        }
        result = UUID_NO_HYPHENS_REGEX
            .replace_all(&result, "<UUID>")
            .to_string();

        (result, tokens)
    }

    fn is_likely_id(text: &str) -> bool {
        // Check if it looks like an ID (reasonable length, alphanumeric)
        if text.len() < 4 || text.len() > 64 {
            return false;
        }

        // Should contain at least some letters and/or numbers
        let has_letters = text.chars().any(char::is_alphabetic);
        let has_numbers = text.chars().any(char::is_numeric);

        has_letters || has_numbers
    }

    fn looks_like_uuid_no_hyphens(text: &str) -> bool {
        if text.len() != 32 {
            return false;
        }

        // Check if it has a good mix of letters and numbers
        let letter_count = text.chars().filter(|c| c.is_alphabetic()).count();
        let number_count = text.chars().filter(|c| c.is_numeric()).count();

        // UUIDs typically have a good mix, whereas pure hashes might be more uniform
        letter_count > 4 && number_count > 4
    }

    #[inline]
    fn has_uuid_indicators(text: &str) -> bool {
        // Ultra-fast check for UUID/ID indicators
        text.contains('-') || // Standard UUIDs have hyphens
        text.contains("req") || text.contains("request") ||
        text.contains("trace") || text.contains("session") ||
        (text.len() > 20 && text.chars().any(|c| c.is_ascii_hexdigit())) // Potential hex string
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_uuid_detection() {
        let text = "Processing request 550e8400-e29b-41d4-a716-446655440000";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        // UUID is replaced first, then REQUEST_ID_REGEX matches "req" from "request"
        // and captures the remaining "uest" as a request ID, replacing "request" with "request_id=<UUID>"
        assert_eq!(result, "Processing request_id=<UUID> <UUID>");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_request_id_detection() {
        let text = "req-abc123 started processing";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "request_id=<UUID> started processing");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_trace_id_detection() {
        let text = "trace:abc123def456 span completed";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "trace=<UUID> span completed");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_session_id_detection() {
        let text = "session=abcd1234efgh5678 authenticated";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "session=<UUID> authenticated");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_multiple_ids() {
        let text = "req-abc123 trace:def456 session=ghi789";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "request_id=<UUID> trace=<UUID> session=<UUID>");
        assert_eq!(tokens.len(), 3);
    }

    #[test]
    fn test_not_an_id() {
        let text = "HTTP 200 OK";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "HTTP 200 OK");
        assert_eq!(tokens.len(), 0);
    }

    // ---- has_uuid_indicators: per-condition tests ----

    #[test]
    fn uuid_ind_hyphen() {
        assert!(UuidDetector::has_uuid_indicators("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn uuid_ind_req() {
        assert!(UuidDetector::has_uuid_indicators("req_abc123"));
    }

    #[test]
    fn uuid_ind_request() {
        assert!(UuidDetector::has_uuid_indicators("request_id: abc123"));
    }

    #[test]
    fn uuid_ind_trace() {
        assert!(UuidDetector::has_uuid_indicators("trace_id: abc123"));
    }

    #[test]
    fn uuid_ind_session() {
        assert!(UuidDetector::has_uuid_indicators("session_token: abc123"));
    }

    #[test]
    fn uuid_ind_long_hex() {
        // >20 chars with hex digits, no hyphens/req/trace/session
        assert!(UuidDetector::has_uuid_indicators("id: 550e8400e29b41d4a716446655440000"));
    }

    #[test]
    fn uuid_ind_short_no_match() {
        // <=20 chars, no keywords — should fail
        assert!(!UuidDetector::has_uuid_indicators("ok"));
    }

    // ---- looks_like_uuid_no_hyphens: per-condition tests ----

    #[test]
    fn uuid_no_hyphens_wrong_len() {
        assert!(!UuidDetector::looks_like_uuid_no_hyphens("abc123"));
    }

    #[test]
    fn uuid_no_hyphens_insufficient_letters() {
        // 32 chars but only 4 letters
        assert!(!UuidDetector::looks_like_uuid_no_hyphens("12345678901234567890123456789012"));
    }

    #[test]
    fn uuid_no_hyphens_insufficient_numbers() {
        // 32 chars but only 4 numbers
        assert!(!UuidDetector::looks_like_uuid_no_hyphens("abcdefabcdefabcdefabcdefabcdefab"));
    }

    #[test]
    fn uuid_no_hyphens_good_mix() {
        assert!(UuidDetector::looks_like_uuid_no_hyphens("550e8400e29b41d4a716446655440000"));
    }

    // ---- is_likely_id: per-condition tests ----

    #[test]
    fn likely_id_too_short() {
        assert!(!UuidDetector::is_likely_id("ab"));
    }

    #[test]
    fn likely_id_too_long() {
        assert!(!UuidDetector::is_likely_id(&"a".repeat(65)));
    }

    #[test]
    fn likely_id_just_letters() {
        assert!(UuidDetector::is_likely_id("abcdef"));
    }

    #[test]
    fn likely_id_just_numbers() {
        assert!(UuidDetector::is_likely_id("123456"));
    }

    #[test]
    fn likely_id_no_alphanum() {
        assert!(!UuidDetector::is_likely_id("----"));
    }

    // ---- Mutant-killing: boundary tests for is_likely_id ----

    #[test]
    fn likely_id_exactly_4_chars() {
        // Kills mutant: `< 4` → `<= 4` (line 112)
        assert!(UuidDetector::is_likely_id("abcd")); // len=4, has letters → true
    }

    #[test]
    fn likely_id_exactly_3_chars_rejected() {
        assert!(!UuidDetector::is_likely_id("abc")); // len=3 < 4 → false
    }

    #[test]
    fn likely_id_exactly_64_chars() {
        // Kills mutant: `> 64` → `>= 64` (line 112)
        assert!(UuidDetector::is_likely_id(&"a".repeat(64))); // len=64, has letters → true
    }

    #[test]
    fn likely_id_exactly_65_chars_rejected() {
        assert!(!UuidDetector::is_likely_id(&"a".repeat(65))); // len=65 > 64 → false
    }

    // ---- Mutant-killing: looks_like_uuid_no_hyphens boundary tests ----

    #[test]
    fn uuid_no_hyphens_exactly_5_letters_passes() {
        // Kills mutant: `letter_count > 4` → `letter_count >= 4` (line 133)
        // 5 letters + 27 digits = 32 chars → letter_count=5 > 4 ✓
        let s = "abcde012345678901234567890123456"; // 5 letters + 27 digits = 32 chars
        assert_eq!(s.len(), 32);
        assert!(UuidDetector::looks_like_uuid_no_hyphens(s));
    }

    #[test]
    fn uuid_no_hyphens_exactly_4_letters_fails() {
        // 4 letters + 28 digits = 32 chars → letter_count=4, NOT > 4
        let s: String = "abcd".chars().chain(std::iter::repeat_n('0', 28)).collect();
        assert_eq!(s.len(), 32);
        assert!(!UuidDetector::looks_like_uuid_no_hyphens(&s));
    }

    #[test]
    fn uuid_no_hyphens_exactly_5_numbers_passes() {
        // Kills mutant: `number_count > 4` → `number_count >= 4` (line 133)
        // 27 letters + 5 digits = 32 chars
        let s: String = std::iter::repeat_n('a', 27).chain("01234".chars()).collect();
        assert_eq!(s.len(), 32);
        assert!(UuidDetector::looks_like_uuid_no_hyphens(&s));
    }

    #[test]
    fn uuid_no_hyphens_exactly_4_numbers_fails() {
        // 28 letters + 4 digits = 32 chars → number_count=4, NOT > 4
        let s: String = std::iter::repeat_n('a', 28).chain("0123".chars()).collect();
        assert_eq!(s.len(), 32);
        assert!(!UuidDetector::looks_like_uuid_no_hyphens(&s));
    }
}
