use super::Token;
use regex::Regex;
use std::sync::LazyLock;

static UUID_WITHOUT_START_BOUNDARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
        .unwrap()
});

fn standalone_uuids(text: &str) -> impl Iterator<Item = regex::Match<'_>> {
    UUID_WITHOUT_START_BOUNDARY
        .find_iter(text)
        .filter(|m| !glued_to_an_alphanumeric_run(text, m.start()))
}

fn glued_to_an_alphanumeric_run(text: &str, start: usize) -> bool {
    start > 0 && text.as_bytes()[start - 1].is_ascii_alphanumeric()
}

const ULID_LEN: usize = 26;
const CROCKFORD_BASE32_UPPER: &str = "[0-9A-HJKMNP-TV-Z]";
const ULID_FIRST_CHAR: &str = "[0-7]";

static ULID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b{ULID_FIRST_CHAR}{CROCKFORD_BASE32_UPPER}{{{}}}\b",
        ULID_LEN - 1
    ))
    .unwrap()
});

const SYSTEMD_ESCAPED_DASH: &str = r"\x2d";

static SYSTEMD_ESCAPED_UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-fA-F]{8}\\x2d[0-9a-fA-F]{4}\\x2d[0-9a-fA-F]{4}\\x2d[0-9a-fA-F]{4}\\x2d[0-9a-fA-F]{12}\b").unwrap()
});

const ID_NAMED_KEY: &str = "[A-Za-z][A-Za-z0-9]*(?:_id|Id|_ID|ID)";

static ID_NAMED_JSON_FIELD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#""({ID_NAMED_KEY})"\s*:\s*"([A-Za-z0-9][A-Za-z0-9+/=_-]{{2,}})""#
    ))
    .unwrap()
});

const REQUEST_KEY_WITH_ID_SUFFIX: &str = r"(?:req|request)[-_]?id[=:]?\s*";
const REQUEST_KEY_WITH_SEPARATOR: &str = r"(?:req|request)[=:]\s*";
const REQ_DASH_OR_UNDERSCORE_PREFIX: &str = r"req[-_]";

static REQUEST_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?:{REQUEST_KEY_WITH_ID_SUFFIX}|{REQUEST_KEY_WITH_SEPARATOR}|{REQ_DASH_OR_UNDERSCORE_PREFIX})([a-zA-Z0-9][a-zA-Z0-9-_]*)\b"
    ))
    .unwrap()
});

const MIN_GENERIC_ID_LEN: usize = 8;

static GENERIC_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b({ID_NAMED_KEY})=([A-Za-z0-9][A-Za-z0-9-]{{{},}})\b",
        MIN_GENERIC_ID_LEN - 1
    ))
    .unwrap()
});

static TRACE_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btrace[=:]([a-zA-Z0-9-_]+)\b").unwrap());

static SESSION_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsession[=:]([a-zA-Z0-9-_]+)\b").unwrap());

static CORRELATION_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcorrelation[-_]?id[=:]([a-zA-Z0-9-_]+)\b").unwrap());

const MIN_ID_LEN: usize = 4;
const MAX_ID_LEN: usize = 64;
const LONG_HEX_FLOOR: usize = 20;

pub struct UuidDetector;

impl UuidDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::has_uuid_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut tokens = Vec::new();

        let mut result = String::with_capacity(text.len());
        let mut last = 0;
        for m in standalone_uuids(text) {
            tokens.push(Token::Uuid(m.as_str().to_string()));
            result.push_str(&text[last..m.start()]);
            result.push_str("<UUID>");
            last = m.end();
        }
        result.push_str(&text[last..]);

        if result.len() >= ULID_LEN {
            super::fold_matches(&mut result, &mut tokens, &ULID_REGEX, |caps| {
                let id = &caps[0];
                id.bytes()
                    .any(|b| b.is_ascii_alphabetic())
                    .then(|| (Token::Uuid(id.to_string()), "<ULID>".to_string()))
            });
        }

        if result.contains(SYSTEMD_ESCAPED_DASH) {
            for found in SYSTEMD_ESCAPED_UUID_REGEX.find_iter(&result) {
                tokens.push(Token::Uuid(found.as_str().to_string()));
            }
            result = SYSTEMD_ESCAPED_UUID_REGEX
                .replace_all(&result, "<UUID>")
                .to_string();
        }

        for regex in [
            &*REQUEST_ID_REGEX,
            &*TRACE_ID_REGEX,
            &*SESSION_ID_REGEX,
            &*CORRELATION_ID_REGEX,
        ] {
            for caps in regex.captures_iter(&result) {
                let id = caps.get(1).unwrap().as_str();
                if Self::has_id_length_and_a_digit(id) {
                    tokens.push(Token::Uuid(id.to_string()));
                }
            }
            result = regex
                .replace_all(&result, |caps: &regex::Captures| {
                    if Self::has_id_length_and_a_digit(&caps[1]) {
                        Self::keep_prefix(caps)
                    } else {
                        caps[0].to_string()
                    }
                })
                .to_string();
        }

        if Self::has_logfmt_id_key(&result) {
            for caps in GENERIC_ID_REGEX.captures_iter(&result) {
                let value = &caps[2];
                if Self::has_id_length_and_a_digit(value) {
                    tokens.push(Token::Uuid(value.to_string()));
                }
            }
            result = GENERIC_ID_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    if Self::has_id_length_and_a_digit(&caps[2]) {
                        format!("{}=<UUID>", &caps[1])
                    } else {
                        caps[0].to_string()
                    }
                })
                .to_string();
        }

        if result.contains("\":") {
            for caps in ID_NAMED_JSON_FIELD_REGEX.captures_iter(&result) {
                if Self::has_id_length_and_a_digit(&caps[2]) {
                    tokens.push(Token::Uuid(caps[2].to_string()));
                }
            }
            result = ID_NAMED_JSON_FIELD_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    if Self::has_id_length_and_a_digit(&caps[2]) {
                        format!("\"{}\":\"<UUID>\"", &caps[1])
                    } else {
                        caps[0].to_string()
                    }
                })
                .to_string();
        }

        (result, tokens)
    }

    fn has_id_length_and_a_digit(text: &str) -> bool {
        (MIN_ID_LEN..=MAX_ID_LEN).contains(&text.len()) && text.chars().any(char::is_numeric)
    }

    #[inline]
    fn keep_prefix(caps: &regex::Captures) -> String {
        let whole = caps.get(0).unwrap();
        let id = caps.get(1).unwrap();
        debug_assert_eq!(
            id.end(),
            whole.end(),
            "the id must be the last capture and end the match, or the kept prefix is wrong"
        );
        format!("{}<UUID>", &whole.as_str()[..id.start() - whole.start()])
    }

    fn has_logfmt_id_key(text: &str) -> bool {
        text.contains("id=") || text.contains("Id=") || text.contains("ID=")
    }

    fn has_json_id_key(text: &str) -> bool {
        text.contains("id\":") || text.contains("Id\":") || text.contains("ID\":")
    }

    fn names_a_request_trace_or_session(text: &str) -> bool {
        text.contains("req") || text.contains("trace") || text.contains("session")
    }

    fn may_hold_a_long_hex_string(text: &str) -> bool {
        text.len() > LONG_HEX_FLOOR && text.chars().any(|c| c.is_ascii_hexdigit())
    }

    fn has_uuid_indicators(text: &str) -> bool {
        text.contains('-')
            || text.contains(SYSTEMD_ESCAPED_DASH)
            || Self::has_logfmt_id_key(text)
            || Self::has_json_id_key(text)
            || Self::names_a_request_trace_or_session(text)
            || Self::may_hold_a_long_hex_string(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_uuid_detection() {
        let text = "Processing request 550e8400-e29b-41d4-a716-446655440000";
        let (result, tokens) = UuidDetector::detect_and_replace(text);
        assert_eq!(
            result, "Processing request <UUID>",
            "the prose word `request` stays; only the UUID folds"
        );
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
        let (result, tokens) = UuidDetector::detect_and_replace("req-ab1 started");
        assert_eq!(
            result, "req-ab1 started",
            "a value under MIN_ID_LEN is not an id"
        );
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
    fn a_keyword_before_a_word_is_not_an_id() {
        for text in [
            "user alice session=opened by uid",
            "span done trace=disabled now",
            "request correlation_id=none set",
        ] {
            let (result, tokens) = UuidDetector::detect_and_replace(text);
            assert_eq!(result, text);
            assert!(tokens.is_empty(), "{text}: {tokens:?}");
        }
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
        assert!(
            UuidDetector::has_uuid_indicators("id: 550e8400e29b41d4a716446655440000"),
            "a line over LONG_HEX_FLOOR with a hex digit may hold a hex id"
        );
    }

    #[test]
    fn uuid_ind_short_no_match() {
        assert!(
            !UuidDetector::has_uuid_indicators("ok"),
            "short, no hex run, no id keyword"
        );
    }

    #[test]
    fn uuid_ind_exactly_21_chars_with_hex() {
        let s = "z".repeat(LONG_HEX_FLOOR) + "a";
        assert!(
            UuidDetector::has_uuid_indicators(&s),
            "{} chars with a hex digit is over LONG_HEX_FLOOR",
            s.len()
        );
    }

    #[test]
    fn uuid_ind_exactly_20_chars_with_hex() {
        let s = "z".repeat(LONG_HEX_FLOOR - 1) + "a";
        assert!(
            !UuidDetector::has_uuid_indicators(&s),
            "{} chars is not over LONG_HEX_FLOOR",
            s.len()
        );
    }

    #[test]
    fn uuid_ind_long_no_hex() {
        let s = "z".repeat(25);
        assert!(
            !UuidDetector::has_uuid_indicators(&s),
            "length alone is not enough: the line also needs a hex digit"
        );
    }

    #[test]
    fn likely_id_too_short() {
        assert!(!UuidDetector::has_id_length_and_a_digit("ab"));
    }

    #[test]
    fn likely_id_too_long() {
        assert!(!UuidDetector::has_id_length_and_a_digit(&"a".repeat(65)));
    }

    #[test]
    fn likely_id_just_letters_is_a_word_not_an_id() {
        assert!(!UuidDetector::has_id_length_and_a_digit("abcdef"));
    }

    #[test]
    fn likely_id_just_numbers() {
        assert!(UuidDetector::has_id_length_and_a_digit("123456"));
    }

    #[test]
    fn likely_id_no_alphanum() {
        assert!(!UuidDetector::has_id_length_and_a_digit("----"));
    }

    #[test]
    fn likely_id_exactly_4_chars() {
        assert!(
            UuidDetector::has_id_length_and_a_digit("abc1"),
            "MIN_ID_LEN chars is long enough"
        );
    }

    #[test]
    fn likely_id_exactly_3_chars_rejected() {
        assert!(
            !UuidDetector::has_id_length_and_a_digit("ab1"),
            "one char under MIN_ID_LEN"
        );
    }

    #[test]
    fn likely_id_exactly_64_chars() {
        let s = format!("1{}", "a".repeat(MAX_ID_LEN - 1));
        assert!(
            UuidDetector::has_id_length_and_a_digit(&s),
            "MAX_ID_LEN chars is still an id"
        );
    }

    #[test]
    fn likely_id_exactly_65_chars_rejected() {
        let s = format!("1{}", "a".repeat(MAX_ID_LEN));
        assert!(
            !UuidDetector::has_id_length_and_a_digit(&s),
            "one char over MAX_ID_LEN"
        );
    }

    #[test]
    fn thirty_two_hex_digits_are_not_a_uuid() {
        let (r, _) =
            UuidDetector::detect_and_replace("saddr=02000050A9FEA9FE0000000000000000 req-x");
        assert!(
            r.starts_with("saddr=02000050A9FEA9FE0000000000000000"),
            "32 hex digits are an MD5, the hash detector's, not a UUID: {r}"
        );
    }

    #[test]
    fn uuid_after_an_underscore_is_a_uuid() {
        let (r, t) = UuidDetector::detect_and_replace(
            "key: user_session_550e8400-e29b-41d4-a716-446655440000 and x550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(
            r, "key: user_session_<UUID> and x550e8400-e29b-41d4-a716-446655440000",
            "`_` is a word char but not a glue char: a UUID after it is a UUID; after a letter it is a slice"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ulid_is_an_id() {
        let (r, t) = UuidDetector::detect_and_replace(
            r#"ulid=01K5H2M4N6P8Q0R2S4T6V8W0X2 sources="[01K5H2M4N6P8Q0R2S4T6V8W0X1 01K5H2M4N6P8Q0R2S4T6V8W0X0]" n=01234567890123456789012345"#,
        );
        assert_eq!(
            r,
            r#"ulid=<ULID> sources="[<ULID> <ULID>]" n=01234567890123456789012345"#
        );
        assert_eq!(t.len(), 3);
        for (s, why) in [
            ("01k5h2m4n6p8q0r2s4t6v8w0x2", "lower case is not canonical"),
            (
                "01K5H2M4N6P8Q0R2S4T6V8W0XI",
                "I is outside Crockford base32",
            ),
            ("01K5H2M4N6P8Q0R2S4T6V8W0X22", "27 chars is not ULID_LEN"),
            ("81K5H2M4N6P8Q0R2S4T6V8W0X2", "the first char is past 7"),
        ] {
            let line = format!("id {s} end");
            let (r, _) = UuidDetector::detect_and_replace(&line);
            assert_eq!(r, line, "{why}");
        }
    }

    #[test]
    fn id_field_with_letters_is_an_id_whatever_its_charset() {
        let (r, t) = UuidDetector::detect_and_replace(
            "container_id=def456ghi789 trace_id=5af93g46a2b7c8d9 auid=4294967295 node_id=n7",
        );
        assert_eq!(
            r, "container_id=<UUID> trace_id=<UUID> auid=4294967295 node_id=n7",
            "an id-named key makes a value with a letter and a digit an id whatever its charset"
        );
        assert_eq!(t.len(), 2);
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn request_followed_by_a_word_in_prose_is_not_a_request_id() {
        let (r, t) = UuidDetector::detect_and_replace(
            "Failed to make webhook authenticator request: tokenreviews is forbidden",
        );
        assert_eq!(
            r,
            "Failed to make webhook authenticator request: tokenreviews is forbidden"
        );
        assert!(t.is_empty());
        let (r, _) = UuidDetector::detect_and_replace("request=abc123def done");
        assert_eq!(r, "request=<UUID> done");
        let (r, _) = UuidDetector::detect_and_replace("request: 5f3a9c1e done");
        assert_eq!(r, "request: <UUID> done");
    }
}

#[cfg(test)]
mod shapes_2026_08_29_ids {
    use super::*;

    #[test]
    fn an_escaped_uuid_and_an_id_named_json_field_are_ids() {
        let (r, t) = UuidDetector::detect_and_replace(
            r"var-lib-kubelet-pods-438a97c2\x2d7b77\x2d466d\x2d964d\x2da94c97935530-volumes.mount",
        );
        assert_eq!(r, "var-lib-kubelet-pods-<UUID>-volumes.mount");
        assert_eq!(t.len(), 1);
        let (r, t) =
            UuidDetector::detect_and_replace(r#"{"dir":"/tmp/x","execID":"003d3","level":"info"}"#);
        assert_eq!(r, r#"{"dir":"/tmp/x","execID":"<UUID>","level":"info"}"#);
        assert!(matches!(t[0], Token::Uuid(ref v) if v == "003d3"));
        let (r, _) = UuidDetector::detect_and_replace(r#"{"grpc.method_type":"unary"}"#);
        assert_eq!(r, r#"{"grpc.method_type":"unary"}"#, "not an id-named key");
    }

    #[test]
    fn an_id_named_field_holding_a_plain_word_is_not_an_id() {
        let (r, t) = UuidDetector::detect_and_replace(r#""route_id":"liveness""#);
        assert_eq!(r, r#""route_id":"liveness""#, "a word is left alone: {r}");
        assert!(t.is_empty(), "no token for a plain word: {t:?}");

        let (r, t) = UuidDetector::detect_and_replace(r#""route_id":"a1b2c3d4""#);
        assert_eq!(r, r#""route_id":"<UUID>""#, "a real digit-bearing id: {r}");
        assert!(matches!(&t[..], [Token::Uuid(v)] if v == "a1b2c3d4"));
    }

    #[test]
    fn req_dash_prefixed_plain_word_is_not_an_id() {
        let (r, t) = UuidDetector::detect_and_replace("req-inform failed");
        assert_eq!(r, "req-inform failed", "a word is left alone: {r}");
        assert!(t.is_empty(), "no token for a plain word: {t:?}");

        let (r, t) = UuidDetector::detect_and_replace("req-inform42 failed");
        assert_eq!(r, "req-<UUID> failed");
        assert!(matches!(&t[..], [Token::Uuid(v)] if v == "inform42"));
    }
}

#[cfg(test)]
mod id_indicator_and_prose_edges {
    use super::*;

    #[test]
    fn each_indicator_alone_admits_a_line() {
        for yes in [
            "x-y",
            "a\\x2db",
            "user_id=12345678",
            "Id=1",
            "ID=1",
            "\"id\":1",
            "\"Id\":1",
            "\"ID\":1",
            "req",
            "request",
            "trace",
            "session",
            "abcdef0123456789abcdef0123456789",
        ] {
            assert!(UuidDetector::has_uuid_indicators(yes), "{yes}");
        }
        assert!(!UuidDetector::has_uuid_indicators("plain words only"));
    }

    #[test]
    fn a_capitalised_id_field_alone_folds_its_value() {
        let (out, _) = UuidDetector::detect_and_replace("traceId=abc123def456 done");
        assert!(out.contains("traceId=<UUID>"), "{out}");
        let (out, _) = UuidDetector::detect_and_replace("sessionID=abc123def456 done");
        assert!(out.contains("sessionID=<UUID>"), "{out}");
    }

    #[test]
    fn a_word_after_request_is_prose_not_an_id() {
        let (out, _) = UuidDetector::detect_and_replace("request abc done");
        assert_eq!(out, "request abc done");
        let (out, _) = UuidDetector::detect_and_replace("req-abc123 done");
        assert!(out.contains("<UUID>"), "{out}");
    }
}
