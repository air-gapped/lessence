use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Standard UUID format: 8-4-4-4-12 hex digits
static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
        .unwrap()
});

// Request ID patterns. The prose word "request" must never match on its own:
// require an explicit `id` suffix, a `=`/`:` separator, or the `req-`/`req_`
// prefix idiom before capturing a value.
static REQUEST_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:req|request)[-_]?id[=:]?\s*|(?:req|request)[=:]\s*|req[-_])([a-zA-Z0-9][a-zA-Z0-9-_]*)\b")
        .unwrap()
});

// Any `*_id=` / `*Id=` field whose value is 8+ chars with a letter in it:
// `container_id=def456ghi789`, `trace_id=5af93g46...`. A charset the hash
// detector would refuse is still an id here, because the key says so.
static GENERIC_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z][A-Za-z0-9]*(?:_id|Id|_ID|ID))=([A-Za-z0-9][A-Za-z0-9-]{7,})\b")
        .unwrap()
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
            .replace_all(&result, |caps: &regex::Captures| {
                if Self::is_likely_id(&caps[1]) {
                    Self::keep_prefix(caps)
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        // Trace, session and correlation ids all carry the value in group 1
        // and fold to a keyword-prefixed placeholder.
        for regex in [&*TRACE_ID_REGEX, &*SESSION_ID_REGEX, &*CORRELATION_ID_REGEX] {
            for caps in regex.captures_iter(&result) {
                let id = caps.get(1).unwrap().as_str();
                if Self::is_likely_id(id) {
                    tokens.push(Token::Uuid(id.to_string()));
                }
            }
            // Folded whether or not the value looked like an id: the
            // surrounding keyword is evidence enough that the field is one.
            result = regex.replace_all(&result, Self::keep_prefix).to_string();
        }

        if result.contains("id=") || result.contains("Id=") || result.contains("ID=") {
            for caps in GENERIC_ID_REGEX.captures_iter(&result) {
                let value = &caps[2];
                if value.bytes().any(|b| b.is_ascii_alphabetic()) {
                    tokens.push(Token::Uuid(value.to_string()));
                }
            }
            result = GENERIC_ID_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    // a purely numeric id (`auid=4294967295`) is a number
                    if caps[2].bytes().any(|b| b.is_ascii_alphabetic()) {
                        format!("{}=<UUID>", &caps[1])
                    } else {
                        caps[0].to_string()
                    }
                })
                .to_string();
        }

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

    #[inline]
    /// The placeholder replaces the id and nothing else: `req-abc123` becomes
    /// `req-<UUID>`, `trace:abc` becomes `trace:<UUID>`. The value is the
    /// last capture group and ends the match.
    fn keep_prefix(caps: &regex::Captures) -> String {
        let whole = &caps[0];
        let id = &caps[1];
        format!("{}<UUID>", &whole[..whole.len() - id.len()])
    }

    fn has_uuid_indicators(text: &str) -> bool {
        // Ultra-fast check for UUID/ID indicators
        text.contains('-') || // Standard UUIDs have hyphens
        text.contains("id=") || text.contains("Id=") || text.contains("ID=") ||
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
        // The prose word "request" stays intact; only the UUID is replaced.
        assert_eq!(result, "Processing request <UUID>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_prose_request_not_mangled() {
        let text = "Processing request user1 with priority 101";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, text);
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_request_id_with_separator_detected() {
        let (result, tokens) = UuidDetector::detect_and_replace("request_id=abc123 done");
        assert_eq!(result, "request_id=<UUID> done");
        assert_eq!(tokens.len(), 1);

        let (result, _) = UuidDetector::detect_and_replace("request: abc123 done");
        assert_eq!(result, "request: <UUID> done");
    }

    #[test]
    fn test_request_short_value_left_alone() {
        // Captured value fails is_likely_id (< 4 chars) — line stays intact.
        let (result, tokens) = UuidDetector::detect_and_replace("req-ab1 started");
        assert_eq!(result, "req-ab1 started");
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_request_id_detection() {
        let text = "req-abc123 started processing";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "req-<UUID> started processing");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Uuid(_)));
    }

    #[test]
    fn test_trace_id_detection() {
        let text = "trace:abc123def456 span completed";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(result, "trace:<UUID> span completed");
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
        assert_eq!(result, "req-<UUID> trace:<UUID> session=<UUID>");
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
        assert!(UuidDetector::has_uuid_indicators(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
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
        assert!(UuidDetector::has_uuid_indicators(
            "id: 550e8400e29b41d4a716446655440000"
        ));
    }

    #[test]
    fn uuid_ind_short_no_match() {
        // <=20 chars, no keywords — should fail
        assert!(!UuidDetector::has_uuid_indicators("ok"));
    }

    #[test]
    fn uuid_ind_exactly_21_chars_with_hex() {
        // Kills: > 20 → >= 20 boundary
        // 21 chars with a hex digit, no keywords
        let s = "z".repeat(20) + "a"; // 21 chars, 'a' is hex
        assert!(UuidDetector::has_uuid_indicators(&s));
    }

    #[test]
    fn uuid_ind_exactly_20_chars_with_hex() {
        // 20 chars, NOT > 20, should fail (no keywords either)
        let s = "z".repeat(19) + "a"; // 20 chars
        assert!(!UuidDetector::has_uuid_indicators(&s));
    }

    #[test]
    fn uuid_ind_long_no_hex() {
        // >20 chars but NO hex digits → && fails
        // Kills: && with || (would pass if || because len > 20 alone suffices)
        let s = "z".repeat(25); // no hex digits (z is not hex)
        assert!(!UuidDetector::has_uuid_indicators(&s));
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

    /// 32 hex digits with no hyphens are an MD5, the hash detector's.
    #[test]
    fn thirty_two_hex_digits_are_not_a_uuid() {
        let (r, _) =
            UuidDetector::detect_and_replace("saddr=02000050A9FEA9FE0000000000000000 req-x");
        assert!(
            r.starts_with("saddr=02000050A9FEA9FE0000000000000000"),
            "{r}"
        );
    }

    /// An id field's value is an id whatever its charset; a numeric one is
    /// a number and stays for the number detector.
    #[test]
    fn id_field_with_letters_is_an_id_whatever_its_charset() {
        let (r, t) = UuidDetector::detect_and_replace(
            "container_id=def456ghi789 trace_id=5af93g46a2b7c8d9 auid=4294967295 node_id=n7",
        );
        assert_eq!(
            r,
            "container_id=<UUID> trace_id=<UUID> auid=4294967295 node_id=n7"
        );
        assert_eq!(t.len(), 2);
    }
}
