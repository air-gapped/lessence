use super::Token;
use regex::Regex;
use std::sync::LazyLock;

const KEY: &str = "[a-zA-Z][a-zA-Z0-9_.-]*";
const VALUE: &str = r"[^\s,;|]+";

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

static EQUALS_OR_COLON_PAIR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({KEY})\s*[=:]\s*({VALUE})")).unwrap());

static EQUALS_PAIR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({KEY})\s*=\s*({VALUE})")).unwrap());

static GENERAL_PASSES_EQUALS_FIRST: [&LazyLock<Regex>; 2] =
    [&EQUALS_PAIR_REGEX, &EQUALS_OR_COLON_PAIR_REGEX];

const METRICS_RUN_MIN_PAIRS: usize = 3;

static METRICS_RUN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?:\b[A-Za-z_][A-Za-z0-9_]*=-?\d+(?:\.\d+)?\b[ \t]*){{{METRICS_RUN_MIN_PAIRS},}}"
    ))
    .unwrap()
});
static NUMERIC_PAIR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)=(-?\d+(?:\.\d+)?)\b").unwrap());

static JSON_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#""(?P<key>{KEY})"\s*:\s*(?:"(?P<quoted>[^"]+)"|(?P<bare>\d+(?:\.\d+)?)|true|false|null)"#
    ))
    .unwrap()
});

const RUN_OPENERS: [char; 5] = ['"', '\'', ':', '[', '('];
const RUN_CLOSERS: [char; 5] = ['"', '\'', ']', ')', ','];

const URL_SCHEMES: [&str; 3] = ["http://", "https://", "ftp://"];

const VALID_KEYS: [&str; 20] = [
    "timeout",
    "retries",
    "max_connections",
    "port",
    "host",
    "ssl",
    "debug",
    "verbose",
    "user_id",
    "session_id",
    "request_id",
    "attempt_count",
    "failure_rate",
    "success_rate",
    "response_time",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "queue_size",
    "buffer_size",
];
const KEY_SUFFIXES: [&str; 6] = ["_timeout", "_limit", "_size", "_count", "_rate", "_usage"];
const KEY_PREFIXES: [&str; 2] = ["max_", "min_"];
const VALUE_SUFFIXES: [&str; 5] = ["ms", "%", "MB", "KB", "GB"];
const PROGRAMMING_KEYWORDS: [&str; 4] = ["if", "for", "while", "switch"];

const SQL_STATEMENT_SHAPES: [&str; 4] = [
    r"select\b.*\bfrom",
    r"insert\s+into",
    r"update\s+\S+\s+set",
    r"delete\s+from",
];

static SQL_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?i)\b(?:{})\b", SQL_STATEMENT_SHAPES.join("|"))).unwrap()
});

static ACCEPTABLE_PAIR_PREFILTER: LazyLock<Regex> = LazyLock::new(|| {
    let alternation = VALID_KEYS
        .iter()
        .chain(&KEY_SUFFIXES)
        .chain(&KEY_PREFIXES)
        .chain(&VALUE_SUFFIXES)
        .map(|s| regex::escape(s))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&alternation).unwrap()
});

pub struct KeyValueDetector;

impl KeyValueDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::has_pair_chars_and_no_url(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        Self::apply_json_pattern(&mut result, &mut tokens);
        Self::apply_metrics_runs(&mut result, &mut tokens);
        for pass in GENERAL_PASSES_EQUALS_FIRST {
            Self::apply_general_pattern(&mut result, &mut tokens, pass);
        }

        (result, tokens)
    }

    pub(crate) fn has_pair_outside_quotes(text: &str) -> bool {
        let mut quoted = false;
        let mut prev = 0u8;
        for &b in text.as_bytes() {
            match b {
                b'"' if prev != b'\\' => quoted = !quoted,
                b'=' if !quoted => return true,
                _ => {}
            }
            prev = b;
        }
        false
    }

    fn has_pair_chars_and_no_url(text: &str) -> bool {
        (text.contains('=') || text.contains(':'))
            && !URL_SCHEMES.iter().any(|scheme| text.contains(scheme))
    }

    fn is_sentence(quoted_value: &str) -> bool {
        quoted_value.contains(char::is_whitespace)
    }

    fn prefix_through_colon_spacing(whole: &str) -> &str {
        let colon = whole.find(':').unwrap_or(0);
        let value_start = whole[colon + 1..]
            .find(|c: char| !c.is_whitespace())
            .map_or(whole.len(), |i| colon + 1 + i);
        &whole[..value_start]
    }

    fn apply_json_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(text, tokens, &JSON_KV_REGEX, |caps| {
            let key = caps.name("key").unwrap().as_str();
            let quoted = caps.name("quoted");
            if quoted.is_some_and(|m| Self::is_sentence(m.as_str())) {
                return None;
            }
            let value = quoted
                .or_else(|| caps.name("bare"))
                .map_or("null", |m| m.as_str());
            let token = Self::pair(key, value);
            let whole = caps.get(0).unwrap().as_str();
            Some((
                token,
                format!("{}<KEY_VALUE>", Self::prefix_through_colon_spacing(whole)),
            ))
        });
    }

    fn is_bounded_message(text: &str, m: &regex::Match) -> bool {
        let before = text[..m.start()].trim_end().chars().next_back();
        let after = text[m.end()..].trim_start().chars().next();
        let opens = before.is_none_or(|c| RUN_OPENERS.contains(&c));
        let closes = after.is_none_or(|c| RUN_CLOSERS.contains(&c));
        opens && closes
    }

    fn apply_metrics_runs(text: &mut String, tokens: &mut Vec<Token>) {
        if !text.contains('=') {
            return;
        }
        let folded = METRICS_RUN_REGEX.replace_all(text, |run: &regex::Captures| {
            if !Self::is_bounded_message(text, &run.get(0).unwrap()) {
                return run[0].to_string();
            }
            NUMERIC_PAIR_REGEX
                .replace_all(&run[0], |caps: &regex::Captures| {
                    tokens.push(Token::KeyValuePair {
                        key: caps[1].to_lowercase(),
                        value_type: Self::classify_value_type(&caps[2]),
                    });
                    format!("{}=<KEY_VALUE>", &caps[1])
                })
                .into_owned()
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *text = s;
        }
    }

    fn already_folded(value: &str) -> bool {
        value.starts_with("<KEY_VALUE>")
    }

    fn owned_by_duration_detector(value: &str) -> bool {
        Self::classify_value_type(value) == "duration"
    }

    fn apply_general_pattern(text: &mut String, tokens: &mut Vec<Token>, regex: &Regex) {
        if !ACCEPTABLE_PAIR_PREFILTER.is_match(text) || !Self::is_not_sql_statement(text) {
            return;
        }
        let mut out = String::new();
        let mut last = 0;
        for m in regex.find_iter(text) {
            let (key, value) = Self::split_pair(m.as_str());
            if Self::already_folded(value)
                || !Self::is_valid_key_value_pair(key, value)
                || Self::owned_by_duration_detector(value)
            {
                continue;
            }
            tokens.push(Self::pair(key, value));
            out.push_str(&text[last..m.end() - value.len()]);
            out.push_str("<KEY_VALUE>");
            last = m.end();
        }
        if last > 0 {
            out.push_str(&text[last..]);
            *text = out;
        }
    }

    fn split_pair(m: &str) -> (&str, &str) {
        let key_end = m.bytes().position(|b| !is_key_byte(b)).unwrap_or(m.len());
        let rest = m[key_end..].trim_start();
        let value = rest.get(1..).unwrap_or("").trim_start();
        debug_assert!(
            m.ends_with(value),
            "the value is the suffix of its match, so the key and separator before it stay"
        );
        (&m[..key_end], value)
    }

    fn pair(key: &str, value: &str) -> Token {
        Token::KeyValuePair {
            key: key.to_lowercase(),
            value_type: Self::classify_value_type(value),
        }
    }

    fn classify_value_type(value: &str) -> String {
        let lower_value = value.to_lowercase();

        if value.ends_with('%') {
            return "percentage".to_string();
        }

        if value.ends_with("ms") || value.ends_with("us") || value.ends_with("ns") {
            return "duration".to_string();
        }
        if value.ends_with('s')
            && value
                .chars()
                .rev()
                .nth(1)
                .is_some_and(|c| c.is_ascii_digit())
        {
            return "duration".to_string();
        }

        if value.ends_with("MB")
            || value.ends_with("GB")
            || value.ends_with("KB")
            || value.ends_with("bytes")
            || value.ends_with("byte")
        {
            return "size".to_string();
        }

        if value.ends_with("rps")
            || value.ends_with("qps")
            || value.ends_with("/s")
            || value.ends_with("/min")
            || value.ends_with("/hr")
        {
            return "rate".to_string();
        }

        if matches!(
            lower_value.as_str(),
            "true" | "false" | "enabled" | "disabled" | "on" | "off"
        ) {
            return "boolean".to_string();
        }

        if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return "number".to_string();
        }

        if Self::is_ip_address(value) {
            return "ip".to_string();
        }

        if URL_SCHEMES.iter().any(|scheme| value.starts_with(scheme)) {
            return "url".to_string();
        }

        "string".to_string()
    }

    fn is_not_sql_statement(text: &str) -> bool {
        !SQL_STATEMENT.is_match(text)
    }

    fn is_valid_key_value_pair(key: &str, value: &str) -> bool {
        if PROGRAMMING_KEYWORDS.contains(&key) {
            return false;
        }

        VALID_KEYS.contains(&key) || Self::is_common_config_pattern(key, value)
    }

    fn is_common_config_pattern(key: &str, value: &str) -> bool {
        KEY_SUFFIXES.iter().any(|s| key.ends_with(s))
            || KEY_PREFIXES.iter().any(|p| key.starts_with(p))
            || VALUE_SUFFIXES.iter().any(|s| value.ends_with(s))
    }

    fn is_ip_address(value: &str) -> bool {
        value.parse::<std::net::IpAddr>().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(key: &str, value: &str, line: &str) -> bool {
        KeyValueDetector::is_not_sql_statement(line)
            && KeyValueDetector::is_valid_key_value_pair(key, value)
    }

    #[test]
    fn a_programming_keyword_is_never_a_key_even_with_a_config_shaped_value() {
        for keyword in PROGRAMMING_KEYWORDS {
            let line = format!("progress {keyword}: 10%");
            let (r, t) = KeyValueDetector::detect_and_replace(&line);
            assert_eq!(r, line, "a % value alone would accept {keyword} as a key");
            assert!(t.is_empty(), "{line}: {t:?}");
        }
        let (r, _) = KeyValueDetector::detect_and_replace("progress done: 10%");
        assert_eq!(r, "progress done: <KEY_VALUE>");
    }

    #[test]
    fn an_ipv6_value_classifies_as_an_ip() {
        assert_eq!(KeyValueDetector::classify_value_type("2001:db8::1"), "ip");
        assert_eq!(
            KeyValueDetector::classify_value_type("::ffff:192.0.2.1"),
            "ip"
        );
    }

    #[test]
    fn percentage_values_fold_as_percentage() {
        let metrics_line = "Performance metrics: cpu=75%, memory=60%, disk=45%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(metrics_line);

        assert!(!tokens.is_empty());
        assert!(result.contains("<KEY_VALUE>"));

        let has_percentage = tokens.iter().any(|token| {
            if let Token::KeyValuePair { key: _, value_type } = token {
                value_type == "percentage"
            } else {
                false
            }
        });
        assert!(has_percentage);
    }

    #[test]
    fn allowlisted_keys_fold_whatever_word_precedes_them() {
        let config_line = "Database config: host=localhost, port=5432, ssl=true";
        let (result, tokens) = KeyValueDetector::detect_and_replace(config_line);
        assert_eq!(
            tokens.len(),
            3,
            "host, port and ssl fold on the allowlist, not because config is on the line: {result}"
        );
        assert_eq!(
            result,
            "Database config: host=<KEY_VALUE>, port=<KEY_VALUE>, ssl=<KEY_VALUE>"
        );

        let plain = "Database ready: host=localhost, port=5432, ssl=true";
        let (plain_result, plain_tokens) = KeyValueDetector::detect_and_replace(plain);
        assert_eq!(plain_tokens.len(), 3);
        assert_eq!(
            plain_result,
            "Database ready: host=<KEY_VALUE>, port=<KEY_VALUE>, ssl=<KEY_VALUE>"
        );
    }

    #[test]
    fn a_pair_keeps_its_key() {
        for (line, folded) in [
            ("pool ready timeout=30", "pool ready timeout=<KEY_VALUE>"),
            ("pool ready retries=30", "pool ready retries=<KEY_VALUE>"),
            ("pool ready port=8080", "pool ready port=<KEY_VALUE>"),
            ("pool ready port : 8080", "pool ready port : <KEY_VALUE>"),
        ] {
            let (r, t) = KeyValueDetector::detect_and_replace(line);
            assert_eq!(r, folded);
            assert_eq!(t.len(), 1, "{line}: {t:?}");
        }
    }

    #[test]
    fn a_level_field_is_not_folded() {
        for line in ["pool ready level=error", "pool ready level=info"] {
            let (r, t) = KeyValueDetector::detect_and_replace(line);
            assert_eq!(r, line);
            assert!(t.is_empty(), "{line}: {t:?}");
        }
        let (r, _) = KeyValueDetector::detect_and_replace("level=warn timeout=30");
        assert_eq!(r, "level=warn timeout=<KEY_VALUE>");
    }

    #[test]
    fn a_folded_value_is_not_folded_twice() {
        let (r, t) = KeyValueDetector::detect_and_replace("cfg host=db1 x_count: 4");
        assert_eq!(r, "cfg host=<KEY_VALUE> x_count: <KEY_VALUE>");
        assert_eq!(t.len(), 2, "{t:?}");
        let (r, t) =
            KeyValueDetector::detect_and_replace(r#"stats "NumGC=10 HeapAlloc=5 job_count=7""#);
        assert_eq!(
            r,
            r#"stats "NumGC=<KEY_VALUE> HeapAlloc=<KEY_VALUE> job_count=<KEY_VALUE>""#
        );
        assert_eq!(t.len(), 3, "{t:?}");
    }

    #[test]
    fn a_keyword_elsewhere_on_the_line_does_not_change_a_field() {
        let a = "sshd[3581664]: Invalid user config from 171.251.29.253 port 46400";
        let b = "sshd[3581664]: Invalid user sammy from 171.251.29.253 port 46400";
        let (ra, _) = KeyValueDetector::detect_and_replace(a);
        let (rb, _) = KeyValueDetector::detect_and_replace(b);
        assert_eq!(
            ra.replace("config", "sammy"),
            rb,
            "the username config must not turn sshd[...]: into a pair"
        );
    }

    #[test]
    fn a_dash_separator_does_not_veto_the_line() {
        let line =
            "WARN CircuitBreaker - Circuit breaker is HALF_OPEN, attempt_count=1, failure_rate=65%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(line);
        assert!(
            result.contains("<KEY_VALUE>"),
            "attempt_count is on the allowlist and must fold; logback's Logger - message has a dash on every line: {result}"
        );
        assert!(!tokens.is_empty());
    }

    #[test]
    fn a_run_of_numeric_pairs_is_a_metrics_dump() {
        let (r, t) = KeyValueDetector::detect_and_replace(
            r#"{"level":"info","msg":"Alloc=25451 TotalAlloc=99852 Sys=81560 NumGC=10 Goroutines=154","time":"x"}"#,
        );
        assert_eq!(
            r,
            r#"{"level":<KEY_VALUE>,"msg":"Alloc=<KEY_VALUE> TotalAlloc=<KEY_VALUE> Sys=<KEY_VALUE> NumGC=<KEY_VALUE> Goroutines=<KEY_VALUE>","time":<KEY_VALUE>}"#
        );
        assert_eq!(
            t.iter()
                .filter(|t| matches!(t, Token::KeyValuePair { .. }))
                .count(),
            7
        );
        for line in [
            "type=CRED_ACQ pid=<PID> uid=1000 auid=1000 ses=3 subj=x",
            "level=info endpointID=1680 identity=1 datapathPolicyRevision=22 desiredPolicyRevision=22 subsys=endpoint",
            "retry a=1 b=2 done",
            "took ms=12 count=3 items=4x",
        ] {
            let (r, _) = KeyValueDetector::detect_and_replace(line);
            assert_eq!(
                r, line,
                "the numeric pairs of a run inside a larger record stay literal"
            );
        }
        let (r, _) =
            KeyValueDetector::detect_and_replace("stats: Alloc=25451 TotalAlloc=99852 NumGC=10");
        assert_eq!(
            r,
            "stats: Alloc=<KEY_VALUE> TotalAlloc=<KEY_VALUE> NumGC=<KEY_VALUE>"
        );
    }

    #[test]
    fn json_sentence_value_keeps_its_words() {
        let (r, _) = KeyValueDetector::detect_and_replace(
            r#"{"level":"info","msg":"[ workqueue ] [call] run task[memoryMonitor] with args=&{Threshold:90}","n":5}"#,
        );
        assert_eq!(
            r,
            r#"{"level":<KEY_VALUE>,"msg":"[ workqueue ] [call] run task[memoryMonitor] with args=&{Threshold:90}","n":<KEY_VALUE>}"#
        );
    }

    #[test]
    fn json_pass_keeps_the_source_spacing() {
        let (compact, _) = KeyValueDetector::detect_and_replace(r#"{"level":"info","n":5}"#);
        assert_eq!(compact, r#"{"level":<KEY_VALUE>,"n":<KEY_VALUE>}"#);
        let (spaced, _) = KeyValueDetector::detect_and_replace(r#"{"level": "info", "n": 5}"#);
        assert_eq!(
            spaced, r#"{"level": <KEY_VALUE>, "n": <KEY_VALUE>}"#,
            "the template is of the input; it must not reformat it"
        );
    }

    #[test]
    fn a_dotted_quad_classifies_as_a_number_before_an_ip() {
        assert_eq!(KeyValueDetector::classify_value_type("75%"), "percentage");
        assert_eq!(KeyValueDetector::classify_value_type("250ms"), "duration");
        assert_eq!(KeyValueDetector::classify_value_type("1GB"), "size");
        assert_eq!(KeyValueDetector::classify_value_type("true"), "boolean");
        assert_eq!(KeyValueDetector::classify_value_type("12345"), "number");
        assert_eq!(
            KeyValueDetector::classify_value_type("192.168.1.1"),
            "number",
            "a dotted quad hits the numeric check before the IP check"
        );
    }

    #[test]
    fn classify_duration_single_digit_s() {
        assert_eq!(KeyValueDetector::classify_value_type("5s"), "duration");
    }

    #[test]
    fn classify_boolean_off() {
        assert_eq!(KeyValueDetector::classify_value_type("off"), "boolean");
    }

    #[test]
    fn classify_number_decimal() {
        assert_eq!(KeyValueDetector::classify_value_type("10.5"), "number");
    }

    #[test]
    fn an_empty_value_is_vacuously_a_number() {
        assert_eq!(KeyValueDetector::classify_value_type(""), "number");
    }

    #[test]
    fn classify_rate() {
        assert_eq!(KeyValueDetector::classify_value_type("100rps"), "rate");
    }

    #[test]
    fn kv_indicators_equals() {
        assert!(KeyValueDetector::has_pair_chars_and_no_url("key=value"));
    }

    #[test]
    fn kv_indicators_no_equals_or_colon() {
        assert!(!KeyValueDetector::has_pair_chars_and_no_url("no kv here"));
    }

    #[test]
    fn kv_indicators_url_excluded() {
        assert!(!KeyValueDetector::has_pair_chars_and_no_url(
            "visit https://example.com"
        ));
    }

    #[test]
    fn programming_constructs_and_sql_yield_no_pair() {
        for test_case in [
            "if variable = value then",
            "for i = 1 to 10",
            "SELECT * FROM table WHERE id = 123",
            "Mathematical equation: x=y+z",
        ] {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);
            assert_eq!(tokens.len(), 0, "{test_case}: {tokens:?}");
            assert_eq!(result, test_case);
        }
    }

    #[test]
    fn classify_percentage() {
        assert_eq!(KeyValueDetector::classify_value_type("75%"), "percentage");
    }

    #[test]
    fn classify_duration_ms() {
        assert_eq!(KeyValueDetector::classify_value_type("100ms"), "duration");
    }

    #[test]
    fn classify_duration_us() {
        assert_eq!(KeyValueDetector::classify_value_type("50us"), "duration");
    }

    #[test]
    fn classify_duration_ns() {
        assert_eq!(KeyValueDetector::classify_value_type("200ns"), "duration");
    }

    #[test]
    fn classify_duration_s() {
        assert_eq!(KeyValueDetector::classify_value_type("5s"), "duration");
    }

    #[test]
    fn classify_size_mb() {
        assert_eq!(KeyValueDetector::classify_value_type("512MB"), "size");
    }

    #[test]
    fn classify_size_gb() {
        assert_eq!(KeyValueDetector::classify_value_type("2GB"), "size");
    }

    #[test]
    fn classify_size_kb() {
        assert_eq!(KeyValueDetector::classify_value_type("1024KB"), "size");
    }

    #[test]
    fn classify_size_bytes() {
        assert_eq!(KeyValueDetector::classify_value_type("4096bytes"), "size");
    }

    #[test]
    fn classify_size_byte() {
        assert_eq!(KeyValueDetector::classify_value_type("1byte"), "size");
    }

    #[test]
    fn classify_rate_rps() {
        assert_eq!(KeyValueDetector::classify_value_type("1000rps"), "rate");
    }

    #[test]
    fn classify_rate_qps() {
        assert_eq!(KeyValueDetector::classify_value_type("500qps"), "rate");
    }

    #[test]
    fn classify_rate_per_s() {
        assert_eq!(KeyValueDetector::classify_value_type("100/s"), "rate");
    }

    #[test]
    fn classify_rate_per_min() {
        assert_eq!(KeyValueDetector::classify_value_type("60/min"), "rate");
    }

    #[test]
    fn classify_rate_per_hr() {
        assert_eq!(KeyValueDetector::classify_value_type("3600/hr"), "rate");
    }

    #[test]
    fn classify_bool_true() {
        assert_eq!(KeyValueDetector::classify_value_type("true"), "boolean");
    }

    #[test]
    fn classify_bool_false() {
        assert_eq!(KeyValueDetector::classify_value_type("false"), "boolean");
    }

    #[test]
    fn classify_bool_enabled() {
        assert_eq!(KeyValueDetector::classify_value_type("enabled"), "boolean");
    }

    #[test]
    fn classify_bool_disabled() {
        assert_eq!(KeyValueDetector::classify_value_type("disabled"), "boolean");
    }

    #[test]
    fn classify_bool_on() {
        assert_eq!(KeyValueDetector::classify_value_type("on"), "boolean");
    }

    #[test]
    fn classify_bool_off() {
        assert_eq!(KeyValueDetector::classify_value_type("off"), "boolean");
    }

    #[test]
    fn classify_number() {
        assert_eq!(KeyValueDetector::classify_value_type("42.5"), "number");
    }

    #[test]
    fn is_ip_address_accepts_a_dotted_quad() {
        assert!(KeyValueDetector::is_ip_address("192.168.1.1"));
    }

    #[test]
    fn classify_url_http() {
        assert_eq!(
            KeyValueDetector::classify_value_type("http://example.com"),
            "url"
        );
    }

    #[test]
    fn classify_url_https() {
        assert_eq!(
            KeyValueDetector::classify_value_type("https://example.com"),
            "url"
        );
    }

    #[test]
    fn classify_url_ftp() {
        assert_eq!(
            KeyValueDetector::classify_value_type("ftp://files.com"),
            "url"
        );
    }

    #[test]
    fn classify_string_default() {
        assert_eq!(KeyValueDetector::classify_value_type("hello"), "string");
    }

    #[test]
    fn config_pattern_timeout_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "read_timeout",
            "30s"
        ));
    }

    #[test]
    fn config_pattern_limit_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "connection_limit",
            "100"
        ));
    }

    #[test]
    fn config_pattern_size_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "buffer_size",
            "4096"
        ));
    }

    #[test]
    fn config_pattern_count_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "retry_count",
            "3"
        ));
    }

    #[test]
    fn config_pattern_rate_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "error_rate",
            "0.01"
        ));
    }

    #[test]
    fn config_pattern_usage_suffix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "cpu_usage",
            "75%"
        ));
    }

    #[test]
    fn config_pattern_max_prefix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "max_retries",
            "5"
        ));
    }

    #[test]
    fn config_pattern_min_prefix() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "min_connections",
            "1"
        ));
    }

    #[test]
    fn config_pattern_value_ms() {
        assert!(KeyValueDetector::is_common_config_pattern("delay", "100ms"));
    }

    #[test]
    fn config_pattern_value_pct() {
        assert!(KeyValueDetector::is_common_config_pattern(
            "threshold",
            "50%"
        ));
    }

    #[test]
    fn config_pattern_value_mb() {
        assert!(KeyValueDetector::is_common_config_pattern("heap", "512MB"));
    }

    #[test]
    fn config_pattern_value_kb() {
        assert!(KeyValueDetector::is_common_config_pattern("page", "4KB"));
    }

    #[test]
    fn config_pattern_value_gb() {
        assert!(KeyValueDetector::is_common_config_pattern("disk", "100GB"));
    }

    #[test]
    fn config_pattern_negative() {
        assert!(!KeyValueDetector::is_common_config_pattern("foo", "bar"));
    }

    #[test]
    fn kv_ctx_excludes_if() {
        assert!(!accepted("if", "true", "if x=true then"));
    }

    #[test]
    fn kv_ctx_excludes_for() {
        assert!(!accepted("for", "x", "for i=0; i<n"));
    }

    #[test]
    fn kv_ctx_excludes_while() {
        assert!(!accepted("while", "x", "while x=true"));
    }

    #[test]
    fn kv_ctx_excludes_switch() {
        assert!(!accepted("switch", "x", "switch x=val"));
    }

    #[test]
    fn an_unlisted_key_is_rejected_beside_a_plus() {
        assert!(!accepted("x", "1", "x + y = 1"));
    }

    #[test]
    fn an_unlisted_key_is_rejected_beside_a_minus() {
        assert!(!accepted("x", "1", "x - y = 1"));
    }

    #[test]
    fn an_unlisted_key_is_rejected_beside_a_star() {
        assert!(!accepted("x", "1", "x * y = 1"));
    }

    #[test]
    fn an_unlisted_key_is_rejected_beside_a_slash() {
        assert!(!accepted("x", "1", "x / y = 1"));
    }

    #[test]
    fn kv_ctx_excludes_select() {
        assert!(!accepted("col", "v", "SELECT col FROM t"));
    }

    #[test]
    fn kv_ctx_excludes_insert() {
        assert!(!accepted("col", "v", "INSERT INTO t"));
    }

    #[test]
    fn kv_ctx_excludes_update() {
        assert!(!accepted("col", "v", "UPDATE t SET col=v"));
    }

    #[test]
    fn kv_ctx_excludes_delete_sql() {
        assert!(!accepted("col", "v", "DELETE FROM t"));
    }

    #[test]
    fn kv_ctx_valid_key() {
        assert!(accepted("timeout", "30", "timeout=30"));
    }

    #[test]
    fn a_suffix_shaped_key_is_accepted_off_the_list() {
        assert!(accepted("read_timeout", "100ms", "read_timeout=100ms"));
    }

    #[test]
    fn ip_addr_valid_ipv4() {
        assert!(KeyValueDetector::is_ip_address("192.168.1.1"));
    }

    #[test]
    fn ip_addr_invalid_ipv4() {
        for value in ["999.999.999.999", "1.2.3.4.", "01.2.3.4", "::::", "ab:cd"] {
            assert!(!KeyValueDetector::is_ip_address(value), "{value}");
        }
        assert!(KeyValueDetector::is_ip_address("::ffff:192.0.2.1"));
    }

    #[test]
    fn ip_addr_valid_ipv6() {
        assert!(KeyValueDetector::is_ip_address("2001:db8:0:0:0:0:0:1"));
    }

    #[test]
    fn ip_addr_short() {
        assert!(!KeyValueDetector::is_ip_address("abc"));
    }

    #[test]
    fn ip_addr_three_octets() {
        assert!(!KeyValueDetector::is_ip_address("192.168.1"));
    }

    #[test]
    fn a_percentage_value_folds_by_value_suffix() {
        let input = "Performance metrics: cpu=75%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "cpu=75% folds on its % suffix");
        assert!(!tokens.is_empty(), "cpu=75% yields a pair");
    }

    #[test]
    fn a_json_record_folds_its_one_word_values() {
        let input = r#"{"level": "info", "message": "hello", "component": "web"}"#;
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "JSON pattern should modify text");
        assert!(!tokens.is_empty(), "JSON pattern should produce tokens");
    }

    #[test]
    fn a_listed_key_folds() {
        let input = "timeout=30";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "general pattern should modify text");
        assert!(!tokens.is_empty(), "general pattern should produce tokens");
    }

    #[test]
    fn an_allowed_key_inside_a_select_statement_is_rejected() {
        assert!(!accepted("timeout", "30", "SELECT id FROM users"));
    }

    #[test]
    fn an_allowed_key_inside_a_insert_statement_is_rejected() {
        assert!(!accepted("timeout", "30", "INSERT INTO users VALUES (1)"));
    }

    #[test]
    fn an_allowed_key_inside_a_update_statement_is_rejected() {
        assert!(!accepted("timeout", "30", "UPDATE users SET name='x'"));
    }

    #[test]
    fn an_allowed_key_inside_a_delete_statement_is_rejected() {
        assert!(!accepted("timeout", "30", "DELETE FROM users WHERE id=1"));
    }

    #[test]
    fn kv_ctx_invalid_key_not_in_list_or_pattern() {
        assert!(!accepted("foo", "bar", "foo=bar"));
    }

    #[test]
    fn a_percentage_value_folds_after_any_prefix() {
        let input = "System stats: cpu=85%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert!(!tokens.is_empty(), "cpu=85% yields a pair: {result}");
        assert!(
            result.contains("<KEY_VALUE>"),
            "cpu=85% folds on its % suffix: {result}"
        );
    }

    #[test]
    fn a_prefix_shaped_key_is_accepted_and_sql_still_vetoes_it() {
        assert!(
            accepted("max_retries", "5", "max_retries=5"),
            "a prefix-shaped key is accepted though it is not on the list"
        );
        assert!(
            !accepted("max_retries", "5", "SELECT max_retries FROM t"),
            "the SQL veto holds for a prefix-shaped key"
        );
    }

    #[test]
    fn a_listed_key_is_accepted_without_a_config_shape() {
        for line in ["timeout=30", "setting timeout=30"] {
            assert!(accepted("timeout", "30", line), "{line}");
        }
    }

    #[test]
    fn a_duration_value_is_left_to_the_duration_detector() {
        let (r, _) = KeyValueDetector::detect_and_replace("latency=5ms timeout=30");
        assert_eq!(r, "latency=5ms timeout=<KEY_VALUE>");
    }
}

#[cfg(test)]
mod gate_2026_08_29 {
    use super::*;

    #[test]
    fn the_gate_admits_every_shape_the_passes_accept() {
        let lines = VALID_KEYS
            .iter()
            .map(|k| format!("{k}=1"))
            .chain(KEY_SUFFIXES.iter().map(|s| format!("x{s}=1")))
            .chain(KEY_PREFIXES.iter().map(|p| format!("{p}x=1")))
            .chain(VALUE_SUFFIXES.iter().map(|s| format!("k=1{s}")));
        for line in lines {
            assert!(ACCEPTABLE_PAIR_PREFILTER.is_match(&line), "{line}");
            let (r, t) = KeyValueDetector::detect_and_replace(&line);
            assert!(
                r.contains("<KEY_VALUE>") || line.ends_with("ms"),
                "{line} -> {r}"
            );
            assert_eq!(t.is_empty(), line.ends_with("ms"), "{line}");
        }
        let prose = r#"Operation for "{volumeName:a podName:b}" failed. Error: timed out"#;
        assert!(!ACCEPTABLE_PAIR_PREFILTER.is_match(prose));
        assert_eq!(KeyValueDetector::detect_and_replace(prose).0, prose);
    }

    #[test]
    fn a_pair_is_read_off_its_match() {
        assert_eq!(
            KeyValueDetector::split_pair("timeout : 30"),
            ("timeout", "30")
        );
        assert_eq!(KeyValueDetector::split_pair("a.b-c=x:y"), ("a.b-c", "x:y"));
        let (r, t) = KeyValueDetector::detect_and_replace("Waiting for caches port=8080 host: db");
        assert_eq!(r, "Waiting for caches port=<KEY_VALUE> host: <KEY_VALUE>");
        assert_eq!(t.len(), 2);
    }
}

#[cfg(test)]
mod general_pass_gates {
    use super::*;

    #[test]
    fn a_numeric_run_folds_only_when_bounded_on_both_sides() {
        let (bounded, _) =
            KeyValueDetector::detect_and_replace(r#"stats "NumGC=10 HeapAlloc=5 Sys=7""#);
        assert!(bounded.contains("NumGC=<KEY_VALUE>"), "{bounded}");
        let (open, _) =
            KeyValueDetector::detect_and_replace("NumGC=10 HeapAlloc=5 Sys=7 trailing words");
        assert!(open.contains("NumGC=10"), "{open}");
    }

    #[test]
    fn an_sql_word_in_prose_is_not_a_statement() {
        for (line, folded) in [
            (
                "Failed to update lock timeout=30",
                "Failed to update lock timeout=<KEY_VALUE>",
            ),
            (
                "will delete cached entries port=8080",
                "will delete cached entries port=<KEY_VALUE>",
            ),
            (
                "please select a mirror retries=3",
                "please select a mirror retries=<KEY_VALUE>",
            ),
            (
                "insert disk now timeout=5",
                "insert disk now timeout=<KEY_VALUE>",
            ),
        ] {
            assert_eq!(KeyValueDetector::detect_and_replace(line).0, folded);
        }
        for statement in [
            "select id from users where timeout=30",
            "update jobs set retries=3",
            "insert into t values (timeout=1)",
            "delete from t where port=8080",
        ] {
            assert_eq!(KeyValueDetector::detect_and_replace(statement).0, statement);
        }
    }

    #[test]
    fn a_sql_line_is_left_alone_even_with_pairs_on_it() {
        let line = "SELECT * FROM t WHERE cpu=75% AND memory=60%";
        let (out, tokens) = KeyValueDetector::detect_and_replace(line);
        assert_eq!(out, line);
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn a_line_whose_only_pair_is_a_duration_is_returned_intact() {
        let (out, _) = KeyValueDetector::detect_and_replace("cpu duration=272ms");
        assert_eq!(
            out, "cpu duration=272ms",
            "cpu opens the gate; the only pair is a duration, owned by the duration detector"
        );
    }
}
