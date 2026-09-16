use super::Token;
use regex::{Captures, Regex};
use std::sync::LazyLock;

// A CPU field carrying millicpu is a resource quantity, not minutes.
// Accept plain, JSON and backslash-escaped field delimiters. A field name
// alone is insufficient for unitless values, which can also name CPU IDs.
static CPU_QUANTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:cpu|CPU)(?:[\\"']*\s*[:=]\s*[\\"']*|[ \t]+)([0-9]+(?:\.[0-9]+)?m)(?:$|[\s,}\]"'\\])"#,
    )
    .expect("CPU quantity field pattern must compile")
});

// Decimal numbers (like 3.488101038, 254547.69971015)
// Match decimal numbers that are likely durations or measurements
static DECIMAL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d+\.\d+\b").unwrap());

// Integer numbers (like 12345, 67890) - standalone integers that could be IDs, counts, etc.
// More specific than decimal but broad enough to catch numeric identifiers.
//
// DELIBERATELY aggressive (audit bead lessence-elx, 2026-06-09): folding
// lines that differ only in a numeric field is lessence's core value
// proposition — the README compression numbers depend on it. Lines folded
// this way lose no information: rollup variation annotations surface the
// distinct values (e.g. "number×2 {137, 143}") in both text and JSON
// output. If stricter behavior is ever needed, add an opt-in context-anchor
// mode rather than tightening this default.
static INTEGER_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3,}\b").unwrap()); // 3+ digits to avoid matching small numbers like "3 retries"

// An integer standing alone as the whole value of a JSON field: `"diff_ms":82`.
// The 3-digit floor above exists so prose like "3 retries" survives, but a
// field value is not prose — and leaving it in place meant a latency crossing
// 100 ms changed whether its line folded (bead lessence-8jb). Runs after
// INTEGER_REGEX, on whatever small numbers it left behind; the key is
// preserved, only the value folds.
//
// Deliberately JSON-only. Extending it to bare logfmt (`syscall=42`) was
// measured and rejected: auditd SYSCALL records have ~40 numeric fields, so
// folding all of them pushed records for different syscalls over the
// similarity threshold and merged them (linux_auditd 649 -> 344 output lines).
// The JSON form carries the whole measured win without that.
// auditd's record id: `msg=audit(<epoch>:<seq>)`. The sequence counter is
// a counter whatever its digit count; kept apart 324 boot lines in one corpus.
static AUDIT_SEQ_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\baudit\([^():\s]+:)(\d+)\)").unwrap());

static FIELD_INTEGER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("[A-Za-z_][A-Za-z0-9_.-]*"\s*:\s*)(-?\d+)\b"#)
        .expect("Failed to compile field integer regex")
});

// Duration with units (1.234s, 523ms, 2m30s, 1h15m, 15m27.417653609s)
// Matches various duration formats: Xh, Xm, Xs, Xms, XμS, Xns, combinations like 1h30m, 2m15s
// systemd spells a long one out — `3d 12h 48min 21.967s`, `7h 33min 1.865s`,
// `10min 45.033s` — and each part read alone left the line half literal.
// Both µ (U+00B5, Go) and μ (U+03BC) are microseconds. No quoted form: the
// quotes around a JSON value belong to the record, not the duration.
static DURATION_WITH_UNIT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:\d+d )?(?:\d+h )?(?:\d+min )?\d+(?:\.\d+)?s|\d+d \d+h(?: \d+min)?|\d+h \d+min|\d+h(?:\d+m)?(?:\d+(?:\.\d+)?s)?|\d+m(?:\d+(?:\.\d+)?s)?|\d+(?:\.\d+)?(?:ms|µs|μs|ns|s))\b").unwrap()
});

// An ISO-8601 duration: `PT30M15S`, `P1DT2H`, `PT0.5S`. At least one
// component is required — a bare `P` or `PT` is a word (a time zone).
static ISO_DURATION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bP(?:(?:\d+Y(?:\d+M)?(?:\d+D)?|\d+M(?:\d+D)?|\d+D)(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?|T(?:\d+H(?:\d+M)?(?:\d+(?:\.\d+)?S)?|\d+M(?:\d+(?:\.\d+)?S)?|\d+(?:\.\d+)?S))\b").unwrap()
});

// Kubernetes duration fields (podStartSLOduration=, podStartE2EDuration=)
static K8S_DURATION_FIELD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\w*[Dd]uration=\d+(?:\.\d+)?(?:ms|µs|μs|ns|us|s|m|h)?\b").unwrap()
});

// Memory/file size values (1234567 bytes, 1.2MB, 5.6GB, 128KB)
// Matches integer or decimal numbers followed by size units: bytes, KB, MB, GB, TB, B
// `775.5M memory peak`, `40K`, `9.6G`, `256Mi`: systemd and Kubernetes
// write the unit letter alone, glued to the number.
static SIZE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d+(?:\.\d+)?\s*(?:bytes?|[KMGT]?i?B)\b|\b\d+(?:\.\d+)?[KMGT]i?\b").unwrap()
});

// Memory addresses (0x7fff5fbff8c0): eight or more hex digits. A short
// `0x22` is a type code, an opcode, a flag — a value, not an address.
static MEMORY_ADDR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0x[a-fA-F0-9]{8,}\b").unwrap());

// Percentages (87.3%, CPU: 45%, memory: 78%)
// Matches both integer and decimal percentages: 45%, 87.3%
static PERCENTAGE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d+(?:\.\d+)?%").unwrap());

// HTTP status codes (200, 404, 500, 401, etc.)
// Matches 3-digit codes that are valid HTTP status codes (100-599)
// Must be surrounded by spaces or punctuation to avoid matching parts of IP addresses
static HTTP_STATUS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:status|error|code|returned?)\s+([1-5][0-9][0-9])\b").unwrap()
});

pub struct DurationDetector;

impl DurationDetector {
    /// `\d-` before the run or `-\d` after it: a dashed numeric tuple.
    fn in_dashed_tuple(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b'-' && b[m.start() - 2].is_ascii_digit();
        let after = m.end() + 1 < b.len() && b[m.end()] == b'-' && b[m.end() + 1].is_ascii_digit();
        before || after
    }

    /// `P` then a digit, or `PT` then a digit: the only way an ISO-8601
    /// duration can start. A line without one skips ISO_DURATION_REGEX,
    /// which would otherwise scan every capital P on every line.
    fn has_iso_duration_indicators(text: &str) -> bool {
        let b = text.as_bytes();
        text.match_indices('P').any(|(i, _)| {
            b.get(i + 1).is_some_and(u8::is_ascii_digit)
                || (b.get(i + 1) == Some(&b'T') && b.get(i + 2).is_some_and(u8::is_ascii_digit))
        })
    }

    /// Three digits in a row: enough for INTEGER_REGEX to have something to do.
    fn has_digit_run(text: &str) -> bool {
        text.as_bytes()
            .windows(3)
            .any(|w| w.iter().all(u8::is_ascii_digit))
    }

    /// Called before generic detectors in the full pipeline, and here for
    /// direct duration detection. The placeholder makes later passes inert.
    pub fn cpu_quantities(text: &str) -> (String, Vec<Token>) {
        if !text.contains('m') || !(text.contains("cpu") || text.contains("CPU")) {
            return (text.to_string(), Vec::new());
        }
        let mut tokens = Vec::new();
        let result = CPU_QUANTITY.replace_all(text, |caps: &Captures| {
            let whole = caps.get(0).unwrap();
            let quantity = caps.get(1).unwrap();
            tokens.push(Token::CpuQuantity(quantity.as_str().to_string()));
            format!(
                "{}<CPU_QUANTITY>{}",
                &whole.as_str()[..quantity.start() - whole.start()],
                &whole.as_str()[quantity.end() - whole.start()..]
            )
        });
        (result.into_owned(), tokens)
    }

    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no duration indicators
        if !text.contains('.')
            && !text.contains('%')
            && !text.contains("ms")
            && !text.contains('s')
            && !text.contains('m')
            && !text.contains('h')
            && !text.contains("bytes")
            && !text.contains("KB")
            && !text.contains("MB")
            // an ISO-8601 duration carries its units in capitals
            && !Self::has_iso_duration_indicators(text)
            // a JSON field value carries no unit of its own
            && !text.contains(':')
            // and neither does a bare number: `[Tue <TIMESTAMP> 2024]`
            && !Self::has_digit_run(text)
        {
            return (text.to_string(), Vec::new());
        }

        let (mut result, mut tokens) = Self::cpu_quantities(text);

        if Self::has_iso_duration_indicators(&result) {
            for found in ISO_DURATION_REGEX.find_iter(&result) {
                tokens.push(Token::Duration(found.as_str().to_string()));
            }
            result = ISO_DURATION_REGEX
                .replace_all(&result, "<DURATION>")
                .to_string();
        }

        // Process in order of specificity: each pass folds its own matches
        // away before the next, looser one runs, so `<SIZE>` can never be
        // re-read as a bare number.
        for (regex, placeholder, token) in [
            (
                &*K8S_DURATION_FIELD_REGEX,
                "<DURATION_FIELD>",
                Token::Duration as fn(String) -> Token,
            ),
            (&*DURATION_WITH_UNIT_REGEX, "<DURATION>", Token::Duration),
            (&*MEMORY_ADDR_REGEX, "<ADDR>", Token::Number),
            (&*SIZE_REGEX, "<SIZE>", Token::Size),
        ] {
            for found in regex.find_iter(&result) {
                tokens.push(token(found.as_str().to_string()));
            }
            result = regex.replace_all(&result, placeholder).to_string();
        }

        // HTTP status codes in prose: only a code the registry knows.
        // `exit status 128` is an exit status.
        for cap in HTTP_STATUS_REGEX.captures_iter(&result) {
            if let Some(status_match) = cap.get(1) {
                let status_str = status_match.as_str();
                if let Ok(status_code) = status_str.parse::<u16>()
                    && Self::is_registered_http_status(status_code)
                {
                    tokens.push(Token::HttpStatus(status_code));
                }
            }
        }
        // Replace only the status code part, keeping the context word.
        // Slice via match positions, not length arithmetic — positions are
        // always char boundaries and stay correct if the regex ever grows
        // a suffix after the capture group.
        result = HTTP_STATUS_REGEX
            .replace_all(&result, |caps: &Captures| {
                let full = caps.get(0).unwrap();
                let code = caps.get(1).unwrap();
                if !code
                    .as_str()
                    .parse::<u16>()
                    .is_ok_and(Self::is_registered_http_status)
                {
                    return full.as_str().to_string();
                }
                let context = &full.as_str()[..code.start() - full.start()];
                format!("{context}<HTTP_STATUS>")
            })
            .to_string();

        // Loosest passes last, on whatever text the placeholders left behind.
        for found in PERCENTAGE_REGEX.find_iter(&result) {
            tokens.push(Token::Number(found.as_str().to_string()));
        }
        result = PERCENTAGE_REGEX.replace_all(&result, "<PCT>").to_string();

        // A decimal with another dotted number attached (`3.3.4`) is a
        // version, kept whole.
        for found in DECIMAL_REGEX.find_iter(&result) {
            if !Self::is_dotted_version(&result, &found) {
                tokens.push(Token::Duration(found.as_str().to_string()));
            }
        }
        result = DECIMAL_REGEX
            .replace_all(&result, |caps: &Captures| {
                let m = caps.get(0).unwrap();
                if Self::is_dotted_version(&result, &m) {
                    m.as_str().to_string()
                } else {
                    "<DECIMAL>".to_string()
                }
            })
            .to_string();

        // `192-168-7-0-24` is one identifier: a digit run joined to more
        // digits by dashes on either side is not a number of its own.
        for found in INTEGER_REGEX.find_iter(&result) {
            if !Self::in_dashed_tuple(&result, &found) {
                tokens.push(Token::Number(found.as_str().to_string()));
            }
        }
        let folded = INTEGER_REGEX.replace_all(&result, |caps: &Captures| {
            let m = caps.get(0).unwrap();
            if Self::in_dashed_tuple(&result, &m) {
                m.as_str().to_string()
            } else {
                "<NUMBER>".to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            result = s;
        }

        // JSON field values last, on the small numbers INTEGER_REGEX left
        // behind. Capture-preserving, so the key survives.
        super::fold_matches(&mut result, &mut tokens, &FIELD_INTEGER_REGEX, |caps| {
            let key = caps.get(1).unwrap().as_str();
            let value = caps.get(2).unwrap().as_str();
            Some((Token::Number(value.to_string()), format!("{key}<NUMBER>")))
        });
        if result.contains("audit(") {
            super::fold_matches(&mut result, &mut tokens, &AUDIT_SEQ_REGEX, |caps| {
                let prefix = caps.get(1).unwrap().as_str();
                let seq = caps.get(2).unwrap().as_str();
                Some((Token::Number(seq.to_string()), format!("{prefix}<NUMBER>)")))
            });
        }

        (result, tokens)
    }

    /// IANA-registered HTTP status codes; anything else after "status" or
    /// "code" in prose is some other kind of number.
    fn is_registered_http_status(code: u16) -> bool {
        matches!(
            code,
            100..=103
                | 200..=208
                | 226
                | 300..=308
                | 400..=418
                | 421..=426
                | 428
                | 429
                | 431
                | 451
                | 500..=508
                | 510
                | 511
        )
    }

    /// `3.3` inside `3.3.4`: preceded by `.digit` or followed by `.digit`.
    fn is_dotted_version(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b'.' && b[m.start() - 2].is_ascii_digit();
        let after = m.end() + 1 < b.len() && b[m.end()] == b'.' && b[m.end() + 1].is_ascii_digit();
        before || after
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- structured field values (bead lessence-8jb) ----

    fn fold(text: &str) -> String {
        DurationDetector::detect_and_replace(text).0
    }

    #[test]
    fn cpu_quantities_are_not_minutes() {
        for (line, shown) in [
            (
                "cpu=750m waited 20m",
                "cpu=<CPU_QUANTITY> waited <DURATION>",
            ),
            (
                "limits cpu 750m memory 512Mi",
                "limits cpu <CPU_QUANTITY> memory <SIZE>",
            ),
            (
                r#"{"cpu":"750m","wait":"20m"}"#,
                r#"{"cpu":"<CPU_QUANTITY>","wait":"<DURATION>"}"#,
            ),
            (
                r#"cpu\":\"750m\" wait=20m"#,
                r#"cpu\":\"<CPU_QUANTITY>\" wait=<DURATION>"#,
            ),
            (
                r"\\cpu\\:\\750m\\, wait=20m",
                r"\\cpu\\:\\<CPU_QUANTITY>\\, wait=<DURATION>",
            ),
        ] {
            let (result, tokens) = DurationDetector::detect_and_replace(line);
            assert_eq!(result, shown, "{line}");
            assert!(
                tokens
                    .iter()
                    .any(|t| matches!(t, Token::CpuQuantity(v) if v == "750m"))
            );
            assert!(
                !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Duration(v) if v == "750m"))
            );
        }
        for line in [
            "waited 20m",
            "CPU time: 20m",
            "cpu_duration=20m",
            "notcpu=20m",
            "cpu=20ms",
            "CPU: 1 PID: 123",
            "cpu=45%",
        ] {
            let (_, tokens) = DurationDetector::detect_and_replace(line);
            assert!(
                !tokens.iter().any(|t| matches!(t, Token::CpuQuantity(_))),
                "{line}"
            );
        }
    }

    #[test]
    fn field_integer_folds_independently_of_digit_count() {
        // The bug: a latency crossing 100 ms changed whether its line folded.
        for value in ["4", "82", "123", "4567"] {
            assert_eq!(
                fold(&format!(r#"{{"a":"x","diff_ms":{value}}}"#)),
                r#"{"a":"x","diff_ms":<NUMBER>}"#,
                "diff_ms:{value}"
            );
        }
    }

    #[test]
    fn field_integer_keeps_the_key() {
        assert_eq!(fold(r#"{"health_ms":1}"#), r#"{"health_ms":<NUMBER>}"#);
    }

    #[test]
    fn field_integer_leaves_bare_logfmt_alone() {
        // Deliberate scope limit, not an oversight: see FIELD_INTEGER_REGEX.
        assert_eq!(fold("syscall=42 done"), "syscall=42 done");
    }

    #[test]
    fn field_integer_folds_zero() {
        assert_eq!(fold(r#"{"dedup_ms":0}"#), r#"{"dedup_ms":<NUMBER>}"#);
    }

    #[test]
    fn field_integer_folds_negative() {
        assert_eq!(fold(r#"{"exit":-13}"#), r#"{"exit":<NUMBER>}"#);
    }

    #[test]
    fn field_integer_leaves_prose_alone() {
        // The 3-digit floor on INTEGER_REGEX exists for exactly these.
        assert_eq!(fold("3 retries remaining"), "3 retries remaining");
        assert_eq!(fold("retry 2 of 5"), "retry 2 of 5");
    }

    #[test]
    fn field_integer_requires_a_key() {
        // A bare colon in prose is not a field.
        assert_eq!(fold("waited: 7 units"), "waited: 7 units");
    }

    #[test]
    fn field_integer_does_not_split_a_decimal() {
        // The decimal pass runs first; the field pass must not then eat the
        // integer part of what is left.
        assert_eq!(fold(r#"{"ratio":1.5}"#), r#"{"ratio":<DECIMAL>}"#);
    }

    #[test]
    fn field_integer_emits_a_number_token() {
        let (_, tokens) = DurationDetector::detect_and_replace(r#"{"n":7}"#);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], Token::Number("7".to_string()));
    }

    #[test]
    fn fast_path_still_reaches_a_bare_json_field() {
        // `{"a":1}` carries none of the duration hints the fast path checks.
        assert_eq!(fold(r#"{"a":1}"#), r#"{"a":<NUMBER>}"#);
    }

    #[test]
    fn test_k8s_duration_detection() {
        let text = r#"podStartSLOduration=3.488101038 podStartE2EDuration="3.488101038s""#;
        let (result, tokens) = DurationDetector::detect_and_replace(text);

        println!("Input: {text}");
        println!("Output: {result}");
        println!("Tokens: {tokens:?}");

        assert!(result.contains("<DURATION_FIELD>"));
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_decimal_detection() {
        let text = "value=123.456789 and another=999.111";
        let (result, tokens) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "value=<DECIMAL> and another=<DECIMAL>");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_memory_address() {
        let text = "pointer at 0x7fff5fbff8c0 in memory";
        let (result, _) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "pointer at <ADDR> in memory");
    }

    #[test]
    fn test_percentage() {
        let text = "CPU usage: 87.3% memory: 45.2%";
        let (result, _) = DurationDetector::detect_and_replace(text);

        assert_eq!(result, "CPU usage: <PCT> memory: <PCT>");
    }

    #[test]
    fn test_duration_units() {
        let test_cases = vec![
            (
                "request took 1.234s to complete",
                "request took <DURATION> to complete",
            ),
            ("timeout after 523ms", "timeout after <DURATION>"),
            ("elapsed time: 2m30s", "elapsed time: <DURATION>"),
            ("uptime: 1h15m", "uptime: <DURATION>"),
            ("latency 45μs detected", "latency <DURATION> detected"),
            ("process ran for 3ns", "process ran for <DURATION>"),
            ("combined: 1h30m15s total", "combined: <DURATION> total"),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            assert!(!tokens.is_empty(), "No tokens detected for: {input}");
        }
    }

    #[test]
    fn test_memory_sizes() {
        let test_cases = vec![
            ("file size: 1234567 bytes", "file size: <SIZE>", true),
            (
                "allocated 1.2MB of memory",
                "allocated <SIZE> of memory",
                true,
            ),
            (
                "disk usage: 5.6GB available",
                "disk usage: <SIZE> available",
                true,
            ),
            ("buffer: 128KB allocated", "buffer: <SIZE> allocated", true),
            // "downloaded 2TB of data" is skipped by fast-path pre-filter (no '.', '%', 's', 'm', 'h', etc.)
            ("downloaded 2TB of data", "downloaded 2TB of data", false),
            ("cache: 512 B total", "cache: <SIZE> total", true),
            (
                "memory usage: 1234567 bytes and 5.6GB disk",
                "memory usage: <SIZE> and <SIZE> disk",
                true,
            ),
        ];

        for (input, expected, expect_tokens) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            if expect_tokens {
                assert!(!tokens.is_empty(), "No tokens detected for: {input}");
            }
        }
    }

    /// A short hex literal is a value, an address has eight hex digits or
    /// more; a digit run inside a dashed tuple is not a number of its own.
    #[test]
    fn short_hex_and_dashed_tuples_stay_literal() {
        let (r, _) = DurationDetector::detect_and_replace(
            "vid:1044 type:0x22 at 0x4000104f90 seed 0x51af8014",
        );
        assert_eq!(r, "vid:<NUMBER> type:0x22 at <ADDR> seed <ADDR>");
        let (r, _) = DurationDetector::detect_and_replace(
            "svc net_Default_7_br0_192-168-7-0-24 took 4500 items range 100-200",
        );
        assert_eq!(
            r,
            "svc net_Default_7_br0_192-168-7-0-24 took <NUMBER> items range 100-200"
        );
    }

    #[test]
    fn test_http_status_codes() {
        let test_cases = vec![
            (
                "POST /login returned 401 Unauthorized",
                "POST /login returned <HTTP_STATUS> Unauthorized",
                true,
            ),
            // a bare number is enough to enter the detector; no `s` needed
            (
                "Error 404 not found on page",
                "Error <HTTP_STATUS> not found on page",
                true,
            ),
            (
                "Request completed with status 201",
                "Request completed with status <HTTP_STATUS>",
                true,
            ),
            (
                "HTTP status code 500 internal error",
                "HTTP status code <HTTP_STATUS> internal error",
                true,
            ),
            (
                "Error code 403 forbidden",
                "Error code <HTTP_STATUS> forbidden",
                true,
            ),
        ];

        for (input, expected, expect_tokens) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            if expect_tokens {
                assert!(!tokens.is_empty(), "No tokens detected for: {input}");
            }
        }
    }

    #[test]
    fn test_percentages() {
        let test_cases = vec![
            ("CPU usage: 87.3%", "CPU usage: <PCT>"),
            ("Memory at 45%", "Memory at <PCT>"),
            ("Disk full at 98%", "Disk full at <PCT>"),
            ("Progress: 12.5% complete", "Progress: <PCT> complete"),
            (
                "Stats: CPU: 45%, memory: 78%, disk: 92.1%",
                "Stats: CPU: <PCT>, memory: <PCT>, disk: <PCT>",
            ),
            ("Low usage: 3.14% only", "Low usage: <PCT> only"),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = DurationDetector::detect_and_replace(input);
            println!("Input: {input} -> Output: {result}");
            assert_eq!(result, expected, "Failed for input: {input}");
            assert!(!tokens.is_empty(), "No tokens detected for: {input}");
        }
    }

    #[test]
    fn test_http_status_context_with_multibyte_text() {
        // Multi-byte UTF-8 around the status code must not break the
        // context slice in the replacement closure.
        let (result, tokens) =
            DurationDetector::detect_and_replace("запрос к api.host returned 404 — повтор");
        assert_eq!(result, "запрос к api.host returned <HTTP_STATUS> — повтор");
        assert!(tokens.iter().any(|t| matches!(t, Token::HttpStatus(404))));
    }

    /// `exit status 128` is an exit status: only a registered HTTP code
    /// after "status"/"returned" in prose is an HTTP status.
    #[test]
    fn prose_status_must_be_a_registered_http_code() {
        assert_eq!(
            fold("exit status 128 and returned 404"),
            "exit status <NUMBER> and returned <HTTP_STATUS>"
        );
    }

    #[test]
    fn a_dotted_version_is_not_a_decimal() {
        assert_eq!(
            fold("version 3.3.4 took 1.5 seconds"),
            "version 3.3.4 took <DECIMAL> seconds"
        );
    }

    /// The unit is part of the field: `duration=272ms` and `duration=2.9s`
    /// fold alike, and nothing of the unit is left behind the placeholder.
    #[test]
    fn duration_field_takes_its_unit() {
        assert_eq!(
            fold("duration=272.602256ms and duration=2.9s and duration=15"),
            "<DURATION_FIELD> and <DURATION_FIELD> and <DURATION_FIELD>"
        );
    }

    /// The sequence counter in an audit record id is a counter whatever
    /// its digit count.
    #[test]
    fn audit_sequence_counter_folds() {
        assert_eq!(
            fold("type=NETFILTER_CFG msg=audit(<TIMESTAMP>:17): table=filter"),
            "type=NETFILTER_CFG msg=audit(<TIMESTAMP>:<NUMBER>): table=filter"
        );
        assert_eq!(
            fold("msg=audit(1481076984.827:1734): x"),
            "msg=audit(<DECIMAL>:<NUMBER>): x"
        );
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn a_spelled_out_duration_and_a_bare_unit_size_are_one_value_each() {
        for (input, expected) in [
            (
                "Consumed 3d 12h 48min 21.967s CPU time, 775.5M memory peak, 0B memory swap peak.",
                "Consumed <DURATION> CPU time, <SIZE> memory peak, <SIZE> memory swap peak.",
            ),
            (
                "Consumed 7h 33min 1.865s CPU time, 9.6G memory peak",
                "Consumed <DURATION> CPU time, <SIZE> memory peak",
            ),
            (
                "Consumed 10min 45.033s CPU time, 40K memory swap peak",
                "Consumed <DURATION> CPU time, <SIZE> memory swap peak",
            ),
            (
                "limits cpu 500m memory 256Mi",
                "limits cpu <CPU_QUANTITY> memory <SIZE>",
            ),
            (
                r#""took":"2.000786944s","x":"119.448684ms""#,
                r#""took":"<DURATION>","x":"<DURATION>""#,
            ),
            (
                "waited 3.638µs and 191.38μs",
                "waited <DURATION> and <DURATION>",
            ),
            (
                "PT30M15S scheduled backup running for job-alpha",
                "<DURATION> scheduled backup running for job-alpha",
            ),
            ("retention P1Y2M10DT2H30M ends", "retention <DURATION> ends"),
            (
                "timeout PT0.5S, zone PT, P and PT stay",
                "timeout <DURATION>, zone PT, P and PT stay",
            ),
        ] {
            let (r, _) = DurationDetector::detect_and_replace(input);
            assert_eq!(r, expected, "{input}");
        }
    }
}
