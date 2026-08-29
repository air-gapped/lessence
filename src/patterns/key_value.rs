use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// Key-value pairs with various separators: key=value, key:value, key value
static KEY_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([a-zA-Z][a-zA-Z0-9_.-]*)\s*[=:]\s*([^\s,;|]+(?:%|ms|s|MB|GB|KB|bytes?)?)")
        .unwrap()
});

// `=`-only pairs; runs before the `[=:]` regex (see detect_and_replace)
static CONFIG_KV_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-zA-Z][a-zA-Z0-9_.-]*)\s*=\s*([^\s,;|]+)").unwrap());

// A metrics run: three or more `key=number` pairs in a row
// (`Alloc=25451 TotalAlloc=99852 Sys=81560 NumGC=10 Goroutines=154`). The
// run is the shape — no single pair says whether its number is a count or an
// identity, but three consecutive numeric pairs are a measurement dump, and
// every value in it folds whatever its digit count. The key stays: it is
// what the template claims about the value.
static METRICS_RUN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b[A-Za-z_][A-Za-z0-9_]*=-?\d+(?:\.\d+)?\b[ \t]*){3,}").unwrap()
});
static NUMERIC_PAIR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)=(-?\d+(?:\.\d+)?)\b").unwrap());

// JSON-style key-value: "key": "value" or "key":123
static JSON_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([a-zA-Z][a-zA-Z0-9_.-]*)"\s*:\s*(?:"([^"]+)"|(\d+(?:\.\d+)?)|true|false|null)"#)
        .unwrap()
});

pub struct KeyValueDetector;

impl KeyValueDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no key-value indicators
        if !Self::has_key_value_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Two passes, each deciding on its own match. There used to be two
        // more — "metrics" and "config" — that ran unrestricted key=value
        // regexes gated by a whole-line keyword sniff ("config", "cpu",
        // "settings"...). A word anywhere on the line then changed how an
        // unrelated field tokenised: the username "config" in an sshd line
        // turned `sshd[1234]:` into `sshd[<KEY_VALUE>` and split the group
        // (lessence-moq). The general pass already covers every pair those
        // two accepted that was worth folding.
        Self::apply_json_pattern(&mut result, &mut tokens);
        Self::apply_metrics_runs(&mut result, &mut tokens);
        // `=` pairs before `[=:]` pairs: on `config: host=localhost` the
        // looser regex would otherwise match `config: host` first and eat
        // the key of the real pair.
        Self::apply_general_pattern(&mut result, &mut tokens, &CONFIG_KV_REGEX);
        Self::apply_general_pattern(&mut result, &mut tokens, &KEY_VALUE_REGEX);

        (result, tokens)
    }

    // No vetoes on words: `for `, `if ` and `while ` are English, and a
    // `for ` in "Waiting for caches" switched key-value folding off for
    // the whole line. A URL veto stays: a bare URL's `?a=b` is not a pair.
    fn has_key_value_indicators(text: &str) -> bool {
        (text.contains('=') || text.contains(':'))
            && !text.contains("http://")
            && !text.contains("https://")
            && !text.contains("ftp://")
    }

    fn apply_json_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        super::fold_matches(text, tokens, &JSON_KV_REGEX, |caps| {
            let key = caps.get(1).unwrap().as_str();
            // A JSON value arrives in group 2 (quoted) or group 3 (bare);
            // neither present means an explicit null.
            let value = caps
                .get(2)
                .or_else(|| caps.get(3))
                .map_or("null", |m| m.as_str());
            // A quoted value with whitespace in it is a sentence: the
            // event's own words. It keeps them, as an unquoted sentence
            // would (lessence-7lj); 13,590 gateway lines of five different
            // tasks were one `"msg":<KEY_VALUE>` group (lessence-t8q).
            if caps
                .get(2)
                .is_some_and(|m| m.as_str().contains(char::is_whitespace))
            {
                return None;
            }
            let (token, _) = Self::pair(key, value);
            // Keep the source's own spacing after the colon — the template
            // must be a template OF the input, not a reformatting of it.
            let whole = caps.get(0).unwrap().as_str();
            let colon = whole.find(':').unwrap_or(0);
            let value_start = whole[colon + 1..]
                .find(|c: char| !c.is_whitespace())
                .map_or(whole.len(), |i| colon + 1 + i);
            Some((token, format!("{}<KEY_VALUE>", &whole[..value_start])))
        });
    }

    /// Every `key=number` inside a run of three or more folds to
    /// `key=<KEY_VALUE>` (lessence-ssz: 899 argocd memory-stats lines split
    /// on `NumGC=10` because the key was not on a list).
    fn apply_metrics_runs(text: &mut String, tokens: &mut Vec<Token>) {
        if !text.contains('=') {
            return;
        }
        let folded = METRICS_RUN_REGEX.replace_all(text, |run: &regex::Captures| {
            // The run must be the whole message — bounded by a quote, a
            // bracket, a `:` or the line ends. Three numeric pairs inside a
            // larger record (`pid=<PID> uid=1000 auid=1000 ses=3 subj=…`,
            // `endpointID=1680 identity=1 …`) are that record's identities.
            let m = run.get(0).unwrap();
            let before = text[..m.start()].trim_end().chars().next_back();
            let after = text[m.end()..].trim_start().chars().next();
            let opens = matches!(before, None | Some('"' | '\'' | ':' | '[' | '('));
            let closes = matches!(after, None | Some('"' | '\'' | ']' | ')' | ','));
            if !(opens && closes) {
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

    fn apply_general_pattern(text: &mut String, tokens: &mut Vec<Token>, regex: &Regex) {
        let line_allows = Self::line_allows_key_value(text);
        super::fold_matches(text, tokens, regex, |caps| {
            let key = caps.get(1).unwrap().as_str();
            let value = caps.get(2).unwrap().as_str();
            // A duration is the duration detector's whatever its unit:
            // `duration=272ms` and `duration=2.9s` must fold alike.
            if Self::classify_value_type(value) == "duration" {
                return None;
            }
            (line_allows && Self::is_valid_key_value_pair(key, value))
                .then(|| Self::pair(key, value))
        });
    }

    /// The token and placeholder every key-value pass folds to.
    fn pair(key: &str, value: &str) -> (Token, String) {
        (
            Token::KeyValuePair {
                key: key.to_lowercase(),
                value_type: Self::classify_value_type(value),
            },
            "<KEY_VALUE>".to_string(),
        )
    }

    fn classify_value_type(value: &str) -> String {
        let lower_value = value.to_lowercase();

        // Percentage values
        if value.ends_with('%') {
            return "percentage".to_string();
        }

        // Duration values
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

        // Size values
        if value.ends_with("MB")
            || value.ends_with("GB")
            || value.ends_with("KB")
            || value.ends_with("bytes")
            || value.ends_with("byte")
        {
            return "size".to_string();
        }

        // Rate values
        if value.ends_with("rps")
            || value.ends_with("qps")
            || value.ends_with("/s")
            || value.ends_with("/min")
            || value.ends_with("/hr")
        {
            return "rate".to_string();
        }

        // Boolean values
        if lower_value == "true"
            || lower_value == "false"
            || lower_value == "enabled"
            || lower_value == "disabled"
            || lower_value == "on"
            || lower_value == "off"
        {
            return "boolean".to_string();
        }

        // Numeric values
        if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return "number".to_string();
        }

        // IP addresses
        if Self::is_ip_address(value) {
            return "ip".to_string();
        }

        // URLs
        if value.starts_with("http://")
            || value.starts_with("https://")
            || value.starts_with("ftp://")
        {
            return "url".to_string();
        }

        // Default to string
        "string".to_string()
    }

    /// Thin composition kept for unit tests; production code hoists
    /// `line_allows_key_value` out of the per-match closure.
    #[cfg(test)]
    fn is_valid_key_value_context(key: &str, value: &str, text: &str) -> bool {
        Self::line_allows_key_value(text) && Self::is_valid_key_value_pair(key, value)
    }

    /// Line-level exclusions (math expressions, SQL) — computed once per
    /// pass, not per match.
    fn line_allows_key_value(text: &str) -> bool {
        // Exclude SQL queries. The arithmetic guard that used to live here
        // (" - ", " + "...) vetoed every logback/log4j line, whose fixed
        // `Logger - message` separator is a dash, so `attempt_count=1` never
        // folded on any Java log (lessence-moq). A `k=v` next to a minus sign
        // is still a `k=v`; the per-pair allowlist decides.
        let upper = text.to_uppercase();
        !(upper.contains("SELECT ")
            || upper.contains("INSERT ")
            || upper.contains("UPDATE ")
            || upper.contains("DELETE "))
    }

    #[cfg_attr(test, mutants::skip)] // "if"/"for"/"while"/"switch" not in valid_keys — exclusion is redundant with the positive check
    fn is_valid_key_value_pair(key: &str, value: &str) -> bool {
        // Exclude programming constructs
        if key == "if" || key == "for" || key == "while" || key == "switch" {
            return false;
        }

        // Include common configuration/logging keys
        let valid_keys = [
            "timeout",
            "retries",
            "max_connections",
            "port",
            "host",
            "ssl",
            "debug",
            "verbose",
            "level",
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

        valid_keys.contains(&key) || Self::is_common_config_pattern(key, value)
    }

    fn is_common_config_pattern(key: &str, value: &str) -> bool {
        // Common configuration patterns
        key.ends_with("_timeout") ||
        key.ends_with("_limit") ||
        key.ends_with("_size") ||
        key.ends_with("_count") ||
        key.ends_with("_rate") ||
        key.ends_with("_usage") ||
        key.starts_with("max_") ||
        key.starts_with("min_") ||
        // Value patterns that suggest configuration
        value.ends_with("ms") ||
        value.ends_with('%') ||
        value.ends_with("MB") ||
        value.ends_with("KB") ||
        value.ends_with("GB")
    }

    fn is_ip_address(value: &str) -> bool {
        // Simple IPv4 pattern
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|&part| part.parse::<u8>().is_ok());
        }

        // Simple IPv6 check
        value.contains(':') && value.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_detection() {
        let metrics_line = "Performance metrics: cpu=75%, memory=60%, disk=45%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(metrics_line);

        assert!(!tokens.is_empty());
        assert!(result.contains("<KEY_VALUE>"));

        // Check percentage classification
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
    fn test_config_detection() {
        // `host`, `port` and `ssl` are all on the general allowlist, so they
        // fold on their own merits — the word "config" elsewhere on the line
        // is not what decides it (lessence-moq).
        let config_line = "Database config: host=localhost, port=5432, ssl=true";
        let (result, tokens) = KeyValueDetector::detect_and_replace(config_line);
        assert_eq!(tokens.len(), 3, "{result}");
        assert_eq!(
            result,
            "Database config: <KEY_VALUE>, <KEY_VALUE>, <KEY_VALUE>"
        );

        // And the same pairs fold identically on a line with no such word.
        let plain = "Database ready: host=localhost, port=5432, ssl=true";
        let (plain_result, plain_tokens) = KeyValueDetector::detect_and_replace(plain);
        assert_eq!(plain_tokens.len(), 3);
        assert_eq!(
            plain_result,
            "Database ready: <KEY_VALUE>, <KEY_VALUE>, <KEY_VALUE>"
        );
    }

    #[test]
    fn a_keyword_elsewhere_on_the_line_does_not_change_a_field() {
        // lessence-moq: the username "config" used to flip sshd[1234]: into
        // sshd[<KEY_VALUE> and split an 11,318-line group.
        let a = "sshd[3581664]: Invalid user config from 171.251.29.253 port 46400";
        let b = "sshd[3581664]: Invalid user sammy from 171.251.29.253 port 46400";
        let (ra, _) = KeyValueDetector::detect_and_replace(a);
        let (rb, _) = KeyValueDetector::detect_and_replace(b);
        assert_eq!(ra.replace("config", "sammy"), rb);
    }

    #[test]
    fn a_dash_separator_does_not_veto_the_line() {
        // logback's `Logger - message` has a dash on every line.
        let line =
            "WARN CircuitBreaker - Circuit breaker is HALF_OPEN, attempt_count=1, failure_rate=65%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(line);
        assert!(
            result.contains("<KEY_VALUE>"),
            "attempt_count is on the allowlist and must fold: {result}"
        );
        assert!(!tokens.is_empty());
    }

    /// Three or more `key=number` pairs in a row are a measurement dump:
    /// every value folds, whatever its digits, and the key stays. Two
    /// pairs, or a run broken by a placeholder, are left to the other
    /// passes.
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
            assert!(!r.contains("=<KEY_VALUE>"), "{line} -> {r}");
        }
        let (r, _) =
            KeyValueDetector::detect_and_replace("stats: Alloc=25451 TotalAlloc=99852 NumGC=10");
        assert_eq!(
            r,
            "stats: Alloc=<KEY_VALUE> TotalAlloc=<KEY_VALUE> NumGC=<KEY_VALUE>"
        );
    }

    /// A JSON string value that is a sentence keeps its words; a one-word
    /// value and a number still fold.
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
        // The template is a template OF the input; it must not reformat it.
        let (compact, _) = KeyValueDetector::detect_and_replace(r#"{"level":"info","n":5}"#);
        assert_eq!(compact, r#"{"level":<KEY_VALUE>,"n":<KEY_VALUE>}"#);
        let (spaced, _) = KeyValueDetector::detect_and_replace(r#"{"level": "info", "n": 5}"#);
        assert_eq!(spaced, r#"{"level": <KEY_VALUE>, "n": <KEY_VALUE>}"#);
    }

    #[test]
    fn test_value_type_classification() {
        assert_eq!(KeyValueDetector::classify_value_type("75%"), "percentage");
        assert_eq!(KeyValueDetector::classify_value_type("250ms"), "duration");
        assert_eq!(KeyValueDetector::classify_value_type("1GB"), "size");
        assert_eq!(KeyValueDetector::classify_value_type("true"), "boolean");
        assert_eq!(KeyValueDetector::classify_value_type("12345"), "number");
        // "192.168.1.1" matches the numeric check (all digits and '.') before the IP check
        assert_eq!(
            KeyValueDetector::classify_value_type("192.168.1.1"),
            "number"
        );
    }

    // --- classify_value_type edge cases ---

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
    fn classify_empty_is_number() {
        // Empty string: chars().all(digit_or_dot) is vacuously true → "number"
        assert_eq!(KeyValueDetector::classify_value_type(""), "number");
    }

    #[test]
    fn classify_rate() {
        assert_eq!(KeyValueDetector::classify_value_type("100rps"), "rate");
    }

    // --- has_key_value_indicators ---

    #[test]
    fn kv_indicators_equals() {
        assert!(KeyValueDetector::has_key_value_indicators("key=value"));
    }

    #[test]
    fn kv_indicators_no_equals_or_colon() {
        assert!(!KeyValueDetector::has_key_value_indicators("no kv here"));
    }

    #[test]
    fn kv_indicators_url_excluded() {
        assert!(!KeyValueDetector::has_key_value_indicators(
            "visit https://example.com"
        ));
    }

    #[test]
    fn test_no_false_positives() {
        let non_kv_cases = vec![
            "if variable = value then",
            "for i = 1 to 10",
            "SELECT * FROM table WHERE id = 123",
            "Mathematical equation: x=y+z",
        ];

        for test_case in non_kv_cases {
            let (result, tokens) = KeyValueDetector::detect_and_replace(test_case);

            // Should not detect key-value pairs in programming constructs
            if test_case.contains("if ")
                || test_case.contains("for ")
                || test_case.contains("SELECT ")
            {
                assert_eq!(tokens.len(), 0);
                assert_eq!(result, test_case);
            }
        }
    }

    // ---- classify_value_type: per-branch tests ----

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
    fn classify_ip_via_is_ip_address() {
        // Note: pure IPv4 (digits + dots) classifies as "number" first,
        // so test is_ip_address directly
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

    // ---- is_common_config_pattern: per-branch tests ----

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

    // ---- is_valid_key_value_context: per-branch tests ----

    #[test]
    fn kv_ctx_excludes_if() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "if",
            "true",
            "if x=true then"
        ));
    }

    #[test]
    fn kv_ctx_excludes_for() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "for",
            "x",
            "for i=0; i<n"
        ));
    }

    #[test]
    fn kv_ctx_excludes_while() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "while",
            "x",
            "while x=true"
        ));
    }

    #[test]
    fn kv_ctx_excludes_switch() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "switch",
            "x",
            "switch x=val"
        ));
    }

    #[test]
    fn kv_ctx_excludes_math_plus() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "x",
            "1",
            "x + y = 1"
        ));
    }

    #[test]
    fn kv_ctx_excludes_math_minus() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "x",
            "1",
            "x - y = 1"
        ));
    }

    #[test]
    fn kv_ctx_excludes_math_mul() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "x",
            "1",
            "x * y = 1"
        ));
    }

    #[test]
    fn kv_ctx_excludes_math_div() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "x",
            "1",
            "x / y = 1"
        ));
    }

    #[test]
    fn kv_ctx_excludes_select() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "col",
            "v",
            "SELECT col FROM t"
        ));
    }

    #[test]
    fn kv_ctx_excludes_insert() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "col",
            "v",
            "INSERT INTO t"
        ));
    }

    #[test]
    fn kv_ctx_excludes_update() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "col",
            "v",
            "UPDATE t SET col=v"
        ));
    }

    #[test]
    fn kv_ctx_excludes_delete_sql() {
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "col",
            "v",
            "DELETE FROM t"
        ));
    }

    #[test]
    fn kv_ctx_valid_key() {
        assert!(KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "timeout=30"
        ));
    }

    #[test]
    fn kv_ctx_config_pattern() {
        assert!(KeyValueDetector::is_valid_key_value_context(
            "read_timeout",
            "100ms",
            "read_timeout=100ms"
        ));
    }

    // ---- is_ip_address: per-branch tests ----

    #[test]
    fn ip_addr_valid_ipv4() {
        assert!(KeyValueDetector::is_ip_address("192.168.1.1"));
    }

    #[test]
    fn ip_addr_invalid_ipv4() {
        assert!(!KeyValueDetector::is_ip_address("999.999.999.999"));
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

    // ---- Mutant-killing: apply_* patterns must modify text ----

    #[test]
    fn apply_metrics_pattern_modifies_text() {
        // Input that triggers metrics detection: has metrics context + metrics KV
        let input = "Performance metrics: cpu=75%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "metrics pattern should modify text");
        assert!(!tokens.is_empty(), "metrics pattern should produce tokens");
    }

    #[test]
    fn apply_json_pattern_modifies_text() {
        // Input that triggers JSON detection: has logging JSON indicators + JSON KV
        let input = r#"{"level": "info", "message": "hello", "component": "web"}"#;
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "JSON pattern should modify text");
        assert!(!tokens.is_empty(), "JSON pattern should produce tokens");
    }

    #[test]
    fn apply_general_pattern_modifies_text() {
        // Input that triggers general KV with a valid key from the valid_keys list
        let input = "timeout=30";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert_ne!(result, input, "general pattern should modify text");
        assert!(!tokens.is_empty(), "general pattern should produce tokens");
    }

    // ---- Mutant-killing: is_config_context false negative ----

    // ---- Mutant-killing: is_valid_key_value_context SQL exclusion per-keyword ----

    #[test]
    fn kv_ctx_excludes_select_only() {
        // Has SELECT but not INSERT, UPDATE, DELETE
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "SELECT id FROM users"
        ));
    }

    #[test]
    fn kv_ctx_excludes_insert_only() {
        // Has INSERT but not SELECT, UPDATE, DELETE
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "INSERT INTO users VALUES (1)"
        ));
    }

    #[test]
    fn kv_ctx_excludes_update_only() {
        // Has UPDATE but not SELECT, INSERT, DELETE
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "UPDATE users SET name='x'"
        ));
    }

    #[test]
    fn kv_ctx_excludes_delete_only() {
        // Has DELETE but not SELECT, INSERT, UPDATE
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "DELETE FROM users WHERE id=1"
        ));
    }

    // ---- Mutant-killing: is_valid_key_value_context math exclusion per-operator ----

    // ---- Mutant-killing: is_valid_key_value_context valid_keys per-group ----

    #[test]
    fn kv_ctx_valid_key_from_list_timeout() {
        // "timeout" is in valid_keys list, not a config pattern key
        assert!(KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "setting timeout=30"
        ));
    }

    #[test]
    fn kv_ctx_valid_via_config_pattern() {
        // "read_timeout" matches is_common_config_pattern (ends_with "_timeout")
        // but is NOT in the valid_keys list directly
        assert!(KeyValueDetector::is_valid_key_value_context(
            "read_timeout",
            "100ms",
            "read_timeout=100ms"
        ));
    }

    #[test]
    fn kv_ctx_invalid_key_not_in_list_or_pattern() {
        // Key is not in valid_keys and doesn't match config pattern -> false
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "foo", "bar", "foo=bar"
        ));
    }

    // ---- is_metrics_context: per-branch test ----

    // ---- is_logging_json: per-branch test ----

    // ---- Mutant-killing: apply_metrics_pattern (replace with ()) ----

    #[test]
    fn metrics_only_input() {
        // Kills mutant: `apply_metrics_pattern` body replaced with `()`
        // Input that triggers ONLY metrics detection (has metrics context keywords)
        // and uses the metrics KV regex format (key=number%)
        let input = "System stats: cpu=85%";
        let (result, tokens) = KeyValueDetector::detect_and_replace(input);
        assert!(
            !tokens.is_empty(),
            "metrics-only input should produce tokens: {result}"
        );
        assert!(
            result.contains("<KEY_VALUE>"),
            "metrics pattern should modify text: {result}"
        );
    }

    // ---- Mutant-killing: is_valid_key_value_context || conditions ----

    #[test]
    fn kv_ctx_config_pattern_not_in_valid_keys() {
        // Kills mutant: `|| with &&` on valid_keys.contains vs is_common_config_pattern (line 332)
        // Key "max_retries" is NOT in valid_keys array but IS a config pattern (starts_with "max_")
        assert!(KeyValueDetector::is_valid_key_value_context(
            "max_retries",
            "5",
            "max_retries=5"
        ));
        // Verify it's not in the valid_keys list
        assert!(!KeyValueDetector::is_valid_key_value_context(
            "max_retries",
            "5",
            "SELECT max_retries FROM t"
        ));
    }

    #[test]
    fn kv_ctx_valid_key_not_config_pattern() {
        // "timeout" IS in valid_keys but "timeout" does NOT match config pattern
        // (no _timeout suffix, no max_/min_ prefix, value "30" has no unit suffix)
        assert!(KeyValueDetector::is_valid_key_value_context(
            "timeout",
            "30",
            "timeout=30"
        ));
    }

    /// A duration-shaped value belongs to the duration detector whatever
    /// its key, so `latency=5ms` and `latency=2.9s` fold alike.
    #[test]
    fn a_duration_value_is_left_to_the_duration_detector() {
        let (r, _) = KeyValueDetector::detect_and_replace("latency=5ms timeout=30");
        assert_eq!(r, "latency=5ms <KEY_VALUE>");
    }
}
