use super::Token;
use regex::{Captures, Regex};
use std::sync::LazyLock;

const CPU_FIELD_DELIMITER_PLAIN_JSON_OR_ESCAPED: &str = r#"[\\"']*\s*[:=]\s*[\\"']*"#;
const CPU_WORD_THEN_BLANKS: &str = r"[ \t]+";
const MILLICPU_NEEDS_ITS_M: &str = r"([0-9]+(?:\.[0-9]+)?m)";
const CPU_QUANTITY_END: &str = r#"(?:$|[\s,}\]"'\\])"#;

static CPU_QUANTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?:cpu|CPU)(?:{CPU_FIELD_DELIMITER_PLAIN_JSON_OR_ESCAPED}|{CPU_WORD_THEN_BLANKS}){MILLICPU_NEEDS_ITS_M}{CPU_QUANTITY_END}"
    ))
    .expect("CPU quantity field pattern must compile")
});

static DECIMAL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d+\.\d+\b").unwrap());

const MIN_FOLDED_INTEGER_DIGITS: usize = 3;

static INTEGER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\b\d{{{MIN_FOLDED_INTEGER_DIGITS},}}\b")).unwrap());

static AUDIT_SEQ_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\baudit\([^():\s]+:)(\d+)\)").unwrap());

static JSON_FIELD_INTEGER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("[A-Za-z_][A-Za-z0-9_.-]*"\s*:\s*)(-?\d+)\b"#)
        .expect("Failed to compile field integer regex")
});

const MICRO_SIGN_UNITS_U00B5_AND_U03BC: &str = "µs|μs";
const SYSTEMD_SPELLED_TO_SECONDS: &str = r"(?:\d+d )?(?:\d+h )?(?:\d+min )?\d+(?:\.\d+)?s";
const SYSTEMD_SPELLED_DAYS: &str = r"\d+d \d+h(?: \d+min)?";
const SYSTEMD_SPELLED_HOURS: &str = r"\d+h \d+min";
const GO_COMPACT_FROM_HOURS: &str = r"\d+h(?:\d+m)?(?:\d+(?:\.\d+)?s)?";
const GO_COMPACT_FROM_MINUTES: &str = r"\d+m(?:\d+(?:\.\d+)?s)?";

static DURATION_WITH_UNIT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?:{SYSTEMD_SPELLED_TO_SECONDS}|{SYSTEMD_SPELLED_DAYS}|{SYSTEMD_SPELLED_HOURS}|{GO_COMPACT_FROM_HOURS}|{GO_COMPACT_FROM_MINUTES}|\d+(?:\.\d+)?(?:ms|{MICRO_SIGN_UNITS_U00B5_AND_U03BC}|ns|s))\b"
    ))
    .unwrap()
});

const ISO_DATE_PART: &str = r"(?:\d+Y(?:\d+M)?(?:\d+D)?|\d+M(?:\d+D)?|\d+D)";
const ISO_OPTIONAL_TIME_AFTER_A_DATE: &str = r"(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?";
const ISO_TIME_PART_WITH_A_COMPONENT: &str =
    r"T(?:\d+H(?:\d+M)?(?:\d+(?:\.\d+)?S)?|\d+M(?:\d+(?:\.\d+)?S)?|\d+(?:\.\d+)?S)";

static ISO_DURATION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\bP(?:{ISO_DATE_PART}{ISO_OPTIONAL_TIME_AFTER_A_DATE}|{ISO_TIME_PART_WITH_A_COMPONENT})\b"
    ))
    .unwrap()
});

static K8S_DURATION_FIELD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(\w*[Dd]uration=)(\d+(?:\.\d+)?(?:ms|{MICRO_SIGN_UNITS_U00B5_AND_U03BC}|ns|us|s|m|h)?)\b"
    ))
    .unwrap()
});

const SIZE_WITH_A_UNIT_WORD: &str = r"\b\d+(?:\.\d+)?\s*(?:bytes?|[KMGT]?i?B)\b";
const SIZE_WITH_A_BARE_UNIT_LETTER: &str = r"\b\d+(?:\.\d+)?[KMGT]i?\b";

static SIZE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "{SIZE_WITH_A_UNIT_WORD}|{SIZE_WITH_A_BARE_UNIT_LETTER}"
    ))
    .unwrap()
});

const MIN_ADDR_HEX_DIGITS: usize = 8;

static MEMORY_ADDR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\b0x[a-fA-F0-9]{{{MIN_ADDR_HEX_DIGITS},}}\b")).unwrap());

static PERCENTAGE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d+(?:\.\d+)?%").unwrap());

static HTTP_STATUS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:status|error|code|returned?)\s+([1-5][0-9][0-9])\b").unwrap()
});

type MeasurementPass = fn(&mut String, &mut Vec<Token>);

pub struct DurationDetector;

impl DurationDetector {
    const PASSES_MOST_SPECIFIC_FIRST: [MeasurementPass; 8] = [
        Self::fold_iso_durations,
        Self::fold_duration_fields_keeping_their_key,
        Self::fold_units_addresses_and_sizes,
        Self::fold_registered_http_statuses,
        Self::fold_percentages,
        Self::fold_decimals_except_versions,
        Self::fold_integers_except_dashed_tuples,
        Self::fold_json_field_integers_and_audit_sequences,
    ];

    fn in_dashed_tuple(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b'-' && b[m.start() - 2].is_ascii_digit();
        let after = m.end() + 1 < b.len() && b[m.end()] == b'-' && b[m.end() + 1].is_ascii_digit();
        before || after
    }

    fn has_iso_duration_indicators(text: &str) -> bool {
        let b = text.as_bytes();
        text.match_indices('P').any(|(i, _)| {
            b.get(i + 1).is_some_and(u8::is_ascii_digit)
                || (b.get(i + 1) == Some(&b'T') && b.get(i + 2).is_some_and(u8::is_ascii_digit))
        })
    }

    fn has_digit_run(text: &str) -> bool {
        text.as_bytes()
            .windows(MIN_FOLDED_INTEGER_DIGITS)
            .any(|w| w.iter().all(u8::is_ascii_digit))
    }

    fn mentions_cpu_and_a_millicpu_unit(text: &str) -> bool {
        text.contains('m') && (text.contains("cpu") || text.contains("CPU"))
    }

    pub fn cpu_quantities(text: &str) -> (String, Vec<Token>) {
        if !Self::mentions_cpu_and_a_millicpu_unit(text) {
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

    fn has_a_unit_letter_or_a_dot(text: &str) -> bool {
        text.contains('.')
            || text.contains('%')
            || text.contains('s')
            || text.contains('m')
            || text.contains('h')
            || text.contains("KB")
            || text.contains("MB")
    }

    fn may_hold_a_unitless_json_field_value(text: &str) -> bool {
        text.contains(':')
    }

    fn may_hold_a_measurement(text: &str) -> bool {
        Self::has_a_unit_letter_or_a_dot(text)
            || Self::has_iso_duration_indicators(text)
            || Self::may_hold_a_unitless_json_field_value(text)
            || Self::has_digit_run(text)
    }

    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::may_hold_a_measurement(text) {
            return (text.to_string(), Vec::new());
        }

        let (mut result, mut tokens) = Self::cpu_quantities(text);
        for pass in Self::PASSES_MOST_SPECIFIC_FIRST {
            pass(&mut result, &mut tokens);
        }
        (result, tokens)
    }

    fn fold_iso_durations(result: &mut String, tokens: &mut Vec<Token>) {
        if Self::has_iso_duration_indicators(result) {
            for found in ISO_DURATION_REGEX.find_iter(result) {
                tokens.push(Token::Duration(found.as_str().to_string()));
            }
            *result = ISO_DURATION_REGEX
                .replace_all(result, "<DURATION>")
                .to_string();
        }
    }

    fn fold_duration_fields_keeping_their_key(result: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(result, tokens, &K8S_DURATION_FIELD_REGEX, |caps| {
            let key = caps.get(1).unwrap().as_str();
            let value = caps.get(2).unwrap().as_str();
            Some((
                Token::Duration(value.to_string()),
                format!("{key}<DURATION_FIELD>"),
            ))
        });
    }

    fn fold_units_addresses_and_sizes(result: &mut String, tokens: &mut Vec<Token>) {
        for (regex, placeholder, token) in [
            (
                &*DURATION_WITH_UNIT_REGEX,
                "<DURATION>",
                Token::Duration as fn(String) -> Token,
            ),
            (&*MEMORY_ADDR_REGEX, "<ADDR>", Token::Number),
            (&*SIZE_REGEX, "<SIZE>", Token::Size),
        ] {
            for found in regex.find_iter(result) {
                tokens.push(token(found.as_str().to_string()));
            }
            *result = regex.replace_all(result, placeholder).to_string();
        }
    }

    fn fold_registered_http_statuses(result: &mut String, tokens: &mut Vec<Token>) {
        *result = HTTP_STATUS_REGEX
            .replace_all(result, |caps: &Captures| {
                let full = caps.get(0).unwrap();
                let code = caps.get(1).unwrap();
                let Some(status_code) = code
                    .as_str()
                    .parse::<u16>()
                    .ok()
                    .filter(|c| Self::is_registered_http_status(*c))
                else {
                    return full.as_str().to_string();
                };
                tokens.push(Token::HttpStatus(status_code));
                let context_ending_at_the_code = &full.as_str()[..code.start() - full.start()];
                format!("{context_ending_at_the_code}<HTTP_STATUS>")
            })
            .to_string();
    }

    fn fold_percentages(result: &mut String, tokens: &mut Vec<Token>) {
        for found in PERCENTAGE_REGEX.find_iter(result) {
            tokens.push(Token::Number(found.as_str().to_string()));
        }
        *result = PERCENTAGE_REGEX.replace_all(result, "<PCT>").to_string();
    }

    fn fold_unless(
        result: &mut String,
        tokens: &mut Vec<Token>,
        regex: &Regex,
        stays_literal: fn(&str, &regex::Match) -> bool,
        placeholder: &str,
        token: fn(String) -> Token,
    ) {
        let folded = regex.replace_all(result, |caps: &Captures| {
            let m = caps.get(0).unwrap();
            if stays_literal(result, &m) {
                m.as_str().to_string()
            } else {
                tokens.push(token(m.as_str().to_string()));
                placeholder.to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_decimals_except_versions(result: &mut String, tokens: &mut Vec<Token>) {
        Self::fold_unless(
            result,
            tokens,
            &DECIMAL_REGEX,
            Self::is_dotted_version,
            "<DECIMAL>",
            Token::Duration,
        );
    }

    fn fold_integers_except_dashed_tuples(result: &mut String, tokens: &mut Vec<Token>) {
        Self::fold_unless(
            result,
            tokens,
            &INTEGER_REGEX,
            Self::in_dashed_tuple,
            "<NUMBER>",
            Token::Number,
        );
    }

    fn fold_json_field_integers_and_audit_sequences(result: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(result, tokens, &JSON_FIELD_INTEGER_REGEX, |caps| {
            let key = caps.get(1).unwrap().as_str();
            let value = caps.get(2).unwrap().as_str();
            Some((Token::Number(value.to_string()), format!("{key}<NUMBER>")))
        });
        if result.contains("audit(") {
            super::fold_matches(result, tokens, &AUDIT_SEQ_REGEX, |caps| {
                let prefix = caps.get(1).unwrap().as_str();
                let seq = caps.get(2).unwrap().as_str();
                Some((Token::Number(seq.to_string()), format!("{prefix}<NUMBER>)")))
            });
        }
    }

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
        for value in ["4", "82", "123", "4567"] {
            assert_eq!(
                fold(&format!(r#"{{"a":"x","diff_ms":{value}}}"#)),
                r#"{"a":"x","diff_ms":<NUMBER>}"#,
                "diff_ms:{value}: a latency crossing 100 ms must not change whether its line folds"
            );
        }
    }

    #[test]
    fn field_integer_keeps_the_key() {
        assert_eq!(fold(r#"{"health_ms":1}"#), r#"{"health_ms":<NUMBER>}"#);
    }

    #[test]
    fn field_integer_leaves_bare_logfmt_alone() {
        assert_eq!(
            fold("syscall=42 done"),
            "syscall=42 done",
            "JSON_FIELD_INTEGER_REGEX is JSON-only by design"
        );
    }

    #[test]
    fn auditd_syscall_records_for_different_syscalls_stay_apart() {
        let openat = fold(
            "type=SYSCALL msg=audit(<TIMESTAMP>:<NUMBER>): arch=c000003e syscall=42 success=yes exit=3 a0=7 a1=1 a2=2 a3=0 items=1 ppid=1 pid=88 uid=0 gid=0 ses=4 tty=pts0",
        );
        let execve = fold(
            "type=SYSCALL msg=audit(<TIMESTAMP>:<NUMBER>): arch=c000003e syscall=59 success=yes exit=0 a0=5 a1=9 a2=6 a3=8 items=2 ppid=2 pid=91 uid=0 gid=0 ses=4 tty=pts0",
        );
        assert!(
            openat.contains("syscall=42") && execve.contains("syscall=59"),
            "a bare logfmt integer is not a JSON field value: folding every small auditd field over-merged records for different syscalls: {openat} / {execve}"
        );
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
        assert_eq!(
            fold("3 retries remaining"),
            "3 retries remaining",
            "under MIN_FOLDED_INTEGER_DIGITS prose keeps its numbers"
        );
        assert_eq!(fold("retry 2 of 5"), "retry 2 of 5");
    }

    #[test]
    fn field_integer_requires_a_key() {
        assert_eq!(
            fold("waited: 7 units"),
            "waited: 7 units",
            "a bare colon in prose is not a field"
        );
    }

    #[test]
    fn field_integer_does_not_split_a_decimal() {
        assert_eq!(
            fold(r#"{"ratio":1.5}"#),
            r#"{"ratio":<DECIMAL>}"#,
            "the decimal pass runs first and takes the whole value"
        );
    }

    #[test]
    fn field_integer_emits_a_number_token() {
        let (_, tokens) = DurationDetector::detect_and_replace(r#"{"n":7}"#);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], Token::Number("7".to_string()));
    }

    #[test]
    fn fast_path_still_reaches_a_bare_json_field() {
        assert_eq!(
            fold(r#"{"a":1}"#),
            r#"{"a":<NUMBER>}"#,
            "a JSON field carries no unit hint, only its colon"
        );
    }

    #[test]
    fn k8s_duration_fields_fold_their_values() {
        let text = r#"podStartSLOduration=3.488101038 podStartE2EDuration="3.488101038s""#;
        let (result, tokens) = DurationDetector::detect_and_replace(text);

        assert!(result.contains("<DURATION_FIELD>"), "{result}");
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

    #[test]
    fn a_bare_tb_size_is_skipped_by_the_fast_path() {
        let (result, tokens) = DurationDetector::detect_and_replace("downloaded 2TB of data");
        assert_eq!(
            result, "downloaded 2TB of data",
            "no unit letter, dot, colon or digit run: the fast path skips the line, a known under-fold"
        );
        assert!(tokens.is_empty(), "{tokens:?}");
    }

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

        let (barcode, tokens) = DurationDetector::detect_and_replace("scanned barcode 404 items");
        assert_eq!(
            barcode, "scanned barcode <NUMBER> items",
            "`barcode` is not the word `code`: the number folds, not as a status"
        );
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::HttpStatus(_))),
            "{tokens:?}"
        );
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
        let (result, tokens) =
            DurationDetector::detect_and_replace("запрос к api.host returned 404 — повтор");
        assert_eq!(
            result, "запрос к api.host returned <HTTP_STATUS> — повтор",
            "multibyte text must not break the context slice"
        );
        assert!(tokens.iter().any(|t| matches!(t, Token::HttpStatus(404))));
    }

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

    #[test]
    fn duration_field_takes_its_unit() {
        assert_eq!(
            fold("duration=272.602256ms and duration=2.9s and duration=15"),
            "duration=<DURATION_FIELD> and duration=<DURATION_FIELD> and duration=<DURATION_FIELD>"
        );
    }

    #[test]
    fn duration_field_keeps_its_key() {
        let (result, tokens) = DurationDetector::detect_and_replace(
            "podStartSLOduration=3.488 imagePullDuration=12ms",
        );
        assert_eq!(
            result,
            "podStartSLOduration=<DURATION_FIELD> imagePullDuration=<DURATION_FIELD>"
        );
        assert_eq!(
            tokens,
            vec![
                Token::Duration("3.488".to_string()),
                Token::Duration("12ms".to_string())
            ]
        );
    }

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

#[cfg(test)]
mod dashed_tuple_dotted_version_iso_edges {
    use super::*;

    fn run_at<'a>(text: &'a str, needle: &str) -> regex::Match<'a> {
        let re = Regex::new(&regex::escape(needle)).unwrap();
        re.find(text).unwrap()
    }

    #[test]
    fn a_dashed_tuple_is_seen_on_either_side_and_never_past_the_end() {
        let yes =
            |t: &str, n: &str| assert!(DurationDetector::in_dashed_tuple(t, &run_at(t, n)), "{t}");
        let no =
            |t: &str, n: &str| assert!(!DurationDetector::in_dashed_tuple(t, &run_at(t, n)), "{t}");
        yes("1-2-3", "2");
        yes("2-3", "2");
        yes("1-2", "2");
        no("x-2 3", "2");
        no("2-x", "2");
        no("2-", "2");
        no("12-", "12");
        no("-2", "2");
        no("2 3", "2");
    }

    #[test]
    fn a_dotted_version_is_seen_on_either_side_and_never_past_the_end() {
        let yes = |t: &str, n: &str| {
            assert!(DurationDetector::is_dotted_version(t, &run_at(t, n)), "{t}");
        };
        let no = |t: &str, n: &str| {
            assert!(
                !DurationDetector::is_dotted_version(t, &run_at(t, n)),
                "{t}"
            );
        };
        yes("3.3.4", "3.3");
        yes("1.2.3", "2.3");
        no("x.2.3 5", "2.3");
        no("1x2.3", "2.3");
        no("2.3.x", "2.3");
        no("2.3.", "2.3");
        no("2.3 x", "2.3");
    }

    #[test]
    fn an_iso_duration_needs_a_digit_after_p_or_pt() {
        assert!(DurationDetector::has_iso_duration_indicators("took P1D"));
        assert!(DurationDetector::has_iso_duration_indicators("took PT5M"));
        for no in ["PT", "P", "PTx", "Px", "plain"] {
            assert!(!DurationDetector::has_iso_duration_indicators(no), "{no}");
        }
    }
}
