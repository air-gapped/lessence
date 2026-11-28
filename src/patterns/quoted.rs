use regex::Regex;
use std::sync::LazyLock;

use super::{AnchorSentinel, Token};
use super::{
    duration::DurationDetector, hash::HashDetector, names::NameDetector, network::NetworkDetector,
    path::PathDetector, process::ProcessDetector, timestamp::UnifiedTimestampDetector,
    uuid::UuidDetector,
};

const ESCAPED_OR_PLAIN_CHAR: &str = r#"(?:[^"\\]|\\.)"#;

static QUOTED_STRING_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r#""{ESCAPED_OR_PLAIN_CHAR}*""#)).unwrap());

static DNS_LABEL_LIKE_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9._/-]*[a-z0-9]$").unwrap());

const MIN_IDENT_LEN: usize = 3;

struct TransparentQuotedMemo {
    computed_under: Option<NestedGates>,
    outcomes: std::collections::HashMap<String, QuotedOutcome>,
}

thread_local! {
    static QUOTED_MEMO: std::cell::RefCell<TransparentQuotedMemo> =
        std::cell::RefCell::new(TransparentQuotedMemo {
            computed_under: None,
            outcomes: std::collections::HashMap::new(),
        });
}

impl TransparentQuotedMemo {
    const MAX_ENTRIES: usize = 8192;
    const MAX_KEY_LEN: usize = 256;

    fn key_to(gates: NestedGates) {
        QUOTED_MEMO.with(|m| {
            let mut memo = m.borrow_mut();
            if memo.computed_under.replace(gates) != Some(gates) {
                memo.outcomes.clear();
            }
        });
    }

    fn outcome(quoted_string: &str, compute: impl FnOnce() -> QuotedOutcome) -> QuotedOutcome {
        let cacheable = quoted_string.len() <= Self::MAX_KEY_LEN;
        if cacheable
            && let Some(known) =
                QUOTED_MEMO.with(|m| m.borrow().outcomes.get(quoted_string).cloned())
        {
            return known;
        }
        let outcome = compute();
        if cacheable {
            QUOTED_MEMO.with(|m| {
                let mut memo = m.borrow_mut();
                if memo.outcomes.len() < Self::MAX_ENTRIES {
                    memo.outcomes
                        .insert(quoted_string.to_string(), outcome.clone());
                }
            });
        }
        outcome
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct NestedGates {
    pub timestamps: bool,
    pub paths: bool,
    pub uuids: bool,
    pub ips: bool,
    pub ports: bool,
    pub fqdns: bool,
    pub hashes: bool,
    pub pids: bool,
    pub durations: bool,
    pub names: bool,
}

impl NestedGates {
    pub const ALL: Self = Self {
        timestamps: true,
        paths: true,
        uuids: true,
        ips: true,
        ports: true,
        fqdns: true,
        hashes: true,
        pids: true,
        durations: true,
        names: true,
    };

    pub fn from_config(c: &crate::config::Config) -> Self {
        Self {
            timestamps: c.normalize_timestamps,
            paths: c.normalize_paths,
            uuids: c.normalize_uuids,
            ips: c.normalize_ips,
            ports: c.normalize_ports,
            fqdns: c.normalize_fqdns,
            hashes: c.normalize_hashes,
            pids: c.normalize_pids,
            durations: c.normalize_durations,
            names: c.normalize_names,
        }
    }
}

#[derive(Clone, Debug)]
struct QuotedOutcome {
    replacement: String,
    emits_token: bool,
    vetoed_in_key_position: bool,
}

impl QuotedOutcome {
    fn escaped_json() -> Self {
        Self {
            replacement: "<ESCAPED_JSON>".to_string(),
            emits_token: true,
            vetoed_in_key_position: false,
        }
    }

    fn placeholders_kept_in_their_words(normalized_content: &str) -> Self {
        Self {
            replacement: format!("\"{normalized_content}\""),
            emits_token: true,
            vetoed_in_key_position: false,
        }
    }

    fn instance_name_folded_on_its_shape() -> Self {
        Self {
            replacement: "<QUOTED_STRING>".to_string(),
            emits_token: true,
            vetoed_in_key_position: true,
        }
    }

    fn literal(quoted_string: &str) -> Self {
        Self {
            replacement: quoted_string.to_string(),
            emits_token: false,
            vetoed_in_key_position: false,
        }
    }
}

pub struct QuotedStringDetector;

fn is_json_key(bytes: &[u8], mut quote_end: usize) -> bool {
    while let Some(b) = bytes.get(quote_end) {
        match b {
            b' ' | b'\t' => quote_end += 1,
            b':' => return true,
            _ => return false,
        }
    }
    false
}

type NestedPass = (fn(&NestedGates) -> bool, fn(&str, &NestedGates) -> String);

const NESTED_CASCADE_PATHS_BEFORE_NETWORK_UUIDS_BEFORE_HASHES: [NestedPass; 8] = [
    (
        |g| g.timestamps,
        |s, _| UnifiedTimestampDetector::detect_and_replace(s).0,
    ),
    (|g| g.paths, |s, _| PathDetector::detect_and_replace(s).0),
    (|g| g.uuids, |s, _| UuidDetector::detect_and_replace(s).0),
    (
        |g| g.ips || g.ports || g.fqdns,
        |s, g| NetworkDetector::detect_and_replace(s, g.ips, g.ports, g.fqdns).0,
    ),
    (|g| g.hashes, |s, _| HashDetector::detect_and_replace(s).0),
    (|g| g.pids, |s, _| ProcessDetector::detect_and_replace(s).0),
    (
        |g| g.durations,
        |s, _| DurationDetector::detect_and_replace(s).0,
    ),
    (|g| g.names, |s, _| NameDetector::detect_and_replace(s).0),
];

fn is_escaped_blob(quoted_content: &str) -> bool {
    let no_words = !quoted_content.contains(char::is_whitespace);
    let opens_a_structure_with_escaped_quotes =
        quoted_content.trim_start().starts_with(['{', '[']) && quoted_content.contains("\\\"");
    (no_words || opens_a_structure_with_escaped_quotes)
        && quoted_content.contains('\\')
        && (quoted_content.contains(':')
            || quoted_content.contains('{')
            || quoted_content.contains('['))
}

fn holds_a_cli_option(quoted_content: &str) -> bool {
    quoted_content.contains(AnchorSentinel::CliOptionVisibleToQuoted.start())
}

fn carries_placeholders(quoted_content: &str, normalized_content: &str) -> bool {
    let found_by_the_nested_cascade = normalized_content != quoted_content;
    let already_put_there_by_the_main_pipeline = quoted_content.contains('<');
    found_by_the_nested_cascade || already_put_there_by_the_main_pipeline
}

impl QuotedStringDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        Self::detect_and_replace_with(text, NestedGates::ALL)
    }

    pub fn detect_and_replace_with(text: &str, gates: NestedGates) -> (String, Vec<Token>) {
        if !text.contains('"') {
            return (text.to_string(), Vec::new());
        }
        TransparentQuotedMemo::key_to(gates);
        let mut tokens = Vec::new();

        let result = QUOTED_STRING_PATTERN
            .replace_all(text, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap();
                let quoted_string = matched.as_str();

                let outcome = TransparentQuotedMemo::outcome(quoted_string, || {
                    Self::normalize_quoted(quoted_string, gates)
                });

                if outcome.vetoed_in_key_position && is_json_key(text.as_bytes(), matched.end()) {
                    return quoted_string.to_string();
                }

                if outcome.emits_token {
                    tokens.push(Token::QuotedString(quoted_string.to_string()));
                }
                outcome.replacement
            })
            .into_owned();

        (result, tokens)
    }

    fn is_instance_ident(content: &str) -> bool {
        content.len() >= MIN_IDENT_LEN
            && content.bytes().any(|b| b == b'-' || b.is_ascii_digit())
            && DNS_LABEL_LIKE_VALUE.is_match(content)
    }

    fn normalize_quoted(quoted_string: &str, gates: NestedGates) -> QuotedOutcome {
        let quoted_content = &quoted_string[1..quoted_string.len() - 1];
        let mut normalized_content = quoted_content.to_string();

        for (enabled, run) in NESTED_CASCADE_PATHS_BEFORE_NETWORK_UUIDS_BEFORE_HASHES {
            if enabled(&gates) {
                normalized_content = run(&normalized_content, &gates);
            }
        }

        if is_escaped_blob(quoted_content) && !holds_a_cli_option(quoted_content) {
            QuotedOutcome::escaped_json()
        } else if carries_placeholders(quoted_content, &normalized_content) {
            QuotedOutcome::placeholders_kept_in_their_words(&normalized_content)
        } else if Self::is_instance_ident(quoted_content) {
            QuotedOutcome::instance_name_folded_on_its_shape()
        } else {
            QuotedOutcome::literal(quoted_string)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ip_inside_a_quoted_string_is_found_with_ports_and_names_off() {
        let gates = NestedGates {
            ports: false,
            fqdns: false,
            ..NestedGates::ALL
        };
        let line = r#"job msg="peer 10.1.2.3 refused" ok"#;
        assert_eq!(
            QuotedStringDetector::detect_and_replace_with(line, gates).0,
            r#"job msg="peer <IP> refused" ok"#
        );
    }

    #[test]
    fn a_port_inside_a_quoted_string_is_found_with_ips_and_names_off() {
        let gates = NestedGates {
            ips: false,
            fqdns: false,
            ..NestedGates::ALL
        };
        let line = r#"job msg="peer 10.1.2.3:8443 refused" ok"#;
        assert_eq!(
            QuotedStringDetector::detect_and_replace_with(line, gates).0,
            r#"job msg="peer 10.1.2.3:<PORT> refused" ok"#
        );
    }

    #[test]
    fn the_nested_cascade_honours_the_gates() {
        let line = r#"job msg="started at 2024-01-01T10:00:00Z took 5ms ok""#;
        let all = QuotedStringDetector::detect_and_replace(line).0;
        assert_eq!(
            all,
            r#"job msg="started at <TIMESTAMP> took <DURATION> ok""#
        );
        let no_ts = NestedGates {
            timestamps: false,
            ..NestedGates::ALL
        };
        let off = QuotedStringDetector::detect_and_replace_with(line, no_ts).0;
        assert_eq!(
            off,
            r#"job msg="started at 2024-01-01T10:00:00Z took <DURATION> ok""#
        );
        let no_duration = NestedGates {
            durations: false,
            ..NestedGates::ALL
        };
        let off = QuotedStringDetector::detect_and_replace_with(line, no_duration).0;
        assert_eq!(off, r#"job msg="started at <TIMESTAMP> took 5ms ok""#);
        assert_eq!(QuotedStringDetector::detect_and_replace(line).0, all);
    }

    #[test]
    fn test_mount_operation_quoted_strings() {
        let input = r#"operationExecutor.VerifyControllerAttachedVolume started for volume "csi-log" (UniqueName: "kubernetes.io/host-path/01af48d9-3471-4acf-93aa-689c01b31dff-csi-log") pod "csi-rbdplugin-sr56f" (UID: "01af48d9-3471-4acf-93aa-689c01b31dff")"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        assert_eq!(
            tokens.len(),
            4,
            "csi-log folds on its shape; the other three carry inner patterns"
        );

        assert!(
            !normalized.contains("\"csi-log\""),
            "csi-log is an instance name and should fold: {normalized}"
        );
        assert!(
            normalized.contains("csi-rbdplugin-<SUFFIX>"),
            "pod name suffix should be normalized"
        );
        assert!(normalized.contains("<UUID>"), "UUID should be normalized");
    }

    #[test]
    fn plain_quoted_words_stay_literal() {
        let input = r#"status "started" and "finished" operations"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input);
    }

    #[test]
    fn below_min_ident_len_and_bare_words_stay_literal() {
        let input = r#"value "x" and "ab" but "plain""#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input);
    }

    #[test]
    fn test_duration_normalization_in_quotes() {
        let input1 = r#"error "back-off 5m0s restarting failed""#;
        let input2 = r#"error "back-off 10m0s restarting failed""#;

        let (normalized1, tokens1) = QuotedStringDetector::detect_and_replace(input1);
        let (normalized2, tokens2) = QuotedStringDetector::detect_and_replace(input2);

        assert_eq!(
            normalized1, normalized2,
            "two lines differing only in a duration fold alike"
        );
        assert_eq!(
            normalized1,
            r#"error "back-off <DURATION> restarting failed""#
        );

        assert_eq!(tokens1.len(), 1);
        assert_eq!(tokens2.len(), 1);
    }

    #[test]
    fn test_multiple_patterns_in_quotes() {
        let test_cases = vec![
            (
                r#"error "connection to 192.168.1.1 failed""#,
                r#"error "connection to <IP> failed""#,
            ),
            (
                r#"error "connection to 10.0.0.1 failed""#,
                r#"error "connection to <IP> failed""#,
            ),
            (
                r#"error "volume abc123def456 not found""#,
                r#"error "volume <HASH> not found""#,
            ),
            (
                r#"error "volume def987fed654321 not found""#,
                r#"error "volume <HASH> not found""#,
            ),
            (
                r#"error "pod 550e8400-e29b-41d4-a716-446655440000 terminated""#,
                r#"error "pod <UUID> terminated""#,
            ),
            (
                r#"error "pod 660f9511-f39c-52e5-b827-557766551111 terminated""#,
                r#"error "pod <UUID> terminated""#,
            ),
            (
                r#"error "process 12345 crashed""#,
                r#"error "process <NUMBER> crashed""#,
            ),
            (
                r#"error "process 67890 crashed""#,
                r#"error "process <NUMBER> crashed""#,
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(
                tokens.len(),
                1,
                "Should detect exactly one quoted string token for: {input}"
            );
        }
    }

    #[test]
    fn quoted_strings_differing_only_in_ip_fold_alike() {
        let inputs = vec![
            r#"error "connection to 192.168.1.1 failed""#,
            r#"error "connection to 10.0.0.1 failed""#,
            r#"error "connection to 172.16.0.1 failed""#,
        ];

        let mut normalized_results = Vec::new();
        for input in &inputs {
            let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);
            normalized_results.push(normalized);
            assert_eq!(tokens.len(), 1);
        }

        assert_eq!(normalized_results[0], normalized_results[1]);
        assert_eq!(normalized_results[1], normalized_results[2]);
        assert_eq!(
            normalized_results[0],
            r#"error "connection to <IP> failed""#
        );
    }

    #[test]
    fn test_timestamp_normalization_in_quotes() {
        let test_cases = vec![
            (
                r#"error "backup at 2025-01-20 10:15:30 failed""#,
                r#"error "backup at <TIMESTAMP> failed""#,
            ),
            (
                r#"error "event occurred on 2025-01-20T10:15:30Z""#,
                r#"error "event occurred on <TIMESTAMP>""#,
            ),
            (
                r#"error "log from Jan 20 10:15:30""#,
                r#"error "log from <TIMESTAMP>""#,
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(tokens.len(), 1);
        }
    }

    #[test]
    fn test_path_normalization_in_quotes() {
        let test_cases = vec![
            (
                r#"error "file /var/log/app.log missing""#,
                r#"error "file <PATH> missing""#,
            ),
            (
                r#"error "cannot read /etc/config/settings.yaml""#,
                r#"error "cannot read <PATH>""#,
            ),
            (
                r#"error "http://192.168.1.1:8080/api/v1 unreachable""#,
                r#"error "<PATH> unreachable""#,
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(tokens.len(), 1);
        }
    }

    #[test]
    fn a_sentence_with_a_windows_path_is_a_sentence_not_escaped_json() {
        let (result, tokens) = QuotedStringDetector::detect_and_replace(
            r#"error "path C:\Windows\System32\config invalid""#,
        );
        assert_eq!(
            result, r#"error "path <PATH> invalid""#,
            "backslashes inside a sentence do not make it an escaped blob"
        );
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn quoted_string_escaped_json_bracket_only() {
        let input = r#"data "value\[index\]more" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+bracket should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_colon_only() {
        let input = r#"data "key\:value\:end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+colon should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_brace_only() {
        let input = r#"data "obj\{inner\}end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+brace should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    fn fold_value(value: &str) -> String {
        let (normalized, _) =
            QuotedStringDetector::detect_and_replace(&format!(r#"{{"k":"{value}"}}"#));
        normalized
    }

    #[test]
    fn shape_fold_is_length_independent() {
        for value in [
            "iperf3",
            "rook-ceph",
            "redis-sentinel-wiki",
            "redis-sentinel-wiki-prod",
            "redis-sentinel-wiki-prod-eu",
        ] {
            assert_eq!(
                fold_value(value),
                r#"{"k":<QUOTED_STRING>}"#,
                "{value} ({} chars) should fold on its shape, at any length",
                value.len()
            );
        }
    }

    #[test]
    fn shape_requires_hyphen_or_digit() {
        assert_eq!(
            fold_value("harbor"),
            r#"{"k":"harbor"}"#,
            "a bare lowercase word is shape-identical to an enum value"
        );
        assert_eq!(fold_value("rook-ceph"), r#"{"k":<QUOTED_STRING>}"#);
        assert_eq!(fold_value("iperf3"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_requires_leading_letter() {
        assert_eq!(
            fold_value("2xx"),
            r#"{"k":"2xx"}"#,
            "HttpStatusDetector emits a bare 2xx; folding it would merge 2xx with 5xx"
        );
        assert_eq!(fold_value("a2x"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_requires_trailing_alphanumeric() {
        assert_eq!(fold_value("abc-"), r#"{"k":"abc-"}"#);
        assert_eq!(fold_value("abc-d"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_minimum_length_boundary() {
        assert_eq!(fold_value("a1"), r#"{"k":"a1"}"#);
        assert_eq!(fold_value("a-b"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_rejects_whitespace() {
        assert_eq!(
            fold_value("Update ok-1"),
            r#"{"k":"Update ok-1"}"#,
            "a value with a space is prose, not an instance name"
        );
    }

    #[test]
    fn shape_rejects_uppercase() {
        assert_eq!(fold_value("InfoRefs-Pack"), r#"{"k":"InfoRefs-Pack"}"#);
    }

    #[test]
    fn shape_accepts_slash_for_qualified_names() {
        assert_eq!(
            fold_value("argocd/iperf3"),
            r#"{"k":<QUOTED_STRING>}"#,
            "an app-qualified name is one instance name"
        );
    }

    #[test]
    fn shape_rejects_empty_value() {
        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(r#"{"k":""}"#);
        assert_eq!(normalized, r#"{"k":""}"#);
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn shape_vetoed_when_the_string_is_a_json_key() {
        let (normalized, _) =
            QuotedStringDetector::detect_and_replace(r#"{"app-namespace":"argocd"}"#);
        assert_eq!(
            normalized, r#"{"app-namespace":"argocd"}"#,
            "folding a key erases the record's schema from the template"
        );
    }

    #[test]
    fn a_key_an_inner_detector_rewrote_is_not_vetoed() {
        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(r#"{"10.1.2.3":"up"}"#);
        assert_eq!(
            normalized, r#"{"<IP>":"up"}"#,
            "the veto covers whole-string folds; a rewritten key keeps its quotes and shape"
        );
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn the_key_veto_is_positional_not_cached() {
        let _ = QuotedStringDetector::detect_and_replace(r#"{"app-namespace":"x"}"#);
        assert_eq!(
            fold_value("app-namespace"),
            r#"{"k":<QUOTED_STRING>}"#,
            "the same string vetoed as a key a moment ago folds as a value"
        );
    }

    #[test]
    fn shape_veto_and_fold_of_the_same_string_on_one_line() {
        let (normalized, tokens) =
            QuotedStringDetector::detect_and_replace(r#"{"app-namespace":"app-namespace"}"#);
        assert_eq!(normalized, r#"{"app-namespace":<QUOTED_STRING>}"#);
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn shape_fold_emits_one_quoted_string_token() {
        let (_, tokens) =
            QuotedStringDetector::detect_and_replace(r#"{"k":"redis-sentinel-wiki"}"#);
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens[0],
            Token::QuotedString("\"redis-sentinel-wiki\"".to_string())
        );
    }

    #[test]
    fn claimed_content_beats_the_shape_rule() {
        let normalized = fold_value("build 1.5");
        assert!(
            !normalized.contains("<QUOTED_STRING>"),
            "claimed content must keep its normalized form: {normalized}"
        );
        assert!(normalized.contains("<DECIMAL>"), "{normalized}");
    }

    #[test]
    fn a_sentence_with_an_escape_keeps_its_words() {
        let (r, _) = QuotedStringDetector::detect_and_replace(
            r#"x "[ workqueue ] [call] run task[memoryMonitor] with args=\u0026{Threshold:90}" y"#,
        );
        assert!(!r.contains("<ESCAPED_JSON>"), "{r}");
        assert!(r.contains("run task[memoryMonitor] with args="), "{r}");
        let (r, _) = QuotedStringDetector::detect_and_replace(r#"x "{\"a\": {\"b\": 1}}" y"#);
        assert_eq!(r, "x <ESCAPED_JSON> y");
    }

    #[test]
    fn an_escaped_blob_holding_an_option_name_stays_visible() {
        let blob = |sentinel: AnchorSentinel| {
            format!(r#"x "{{\"argv\":[\"run\",\"{}\"]}}" y"#, sentinel.text(3))
        };
        let with_option = blob(AnchorSentinel::CliOptionVisibleToQuoted);
        let (r, tokens) = QuotedStringDetector::detect_and_replace(&with_option);
        assert_eq!(r, with_option, "the option name inside is an identity");
        assert!(tokens.is_empty(), "{tokens:?}");
        let (r, tokens) =
            QuotedStringDetector::detect_and_replace(&blob(AnchorSentinel::OpaqueToDetectors));
        assert_eq!(r, "x <ESCAPED_JSON> y", "only an option name keeps it open");
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn escaped_json_beats_the_shape_rule() {
        let (normalized, _) = QuotedStringDetector::detect_and_replace(r#"{"k":"a-b\"c:d"}"#);
        assert!(
            normalized.contains("<ESCAPED_JSON>"),
            "escaped JSON keeps priority: {normalized}"
        );
    }

    #[test]
    fn a_quoted_sentence_stays_literal_whatever_its_length() {
        for content in [
            "it is a very simple tex",
            "it is a very simple text",
            "it is a very simple text indeed ok",
        ] {
            let input = format!(r#"x "{content}""#);
            let (result, tokens) = QuotedStringDetector::detect_and_replace(&input);
            assert_eq!(
                result,
                input,
                "prose of {} chars must survive verbatim",
                content.len()
            );
            assert!(tokens.is_empty(), "prose emits no token: {tokens:?}");
        }
    }

    #[test]
    fn a_quoted_sentence_keeps_placeholders_the_pipeline_already_put_in_it() {
        let input = r#"{"msg":"Refreshing app status (expiry: <DURATION>), level (2)"}"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert_eq!(
            result, input,
            "this detector runs last: the nested cascade finds nothing, the placeholders still count"
        );
        assert_eq!(
            tokens.len(),
            1,
            "one QuotedString token for the claimed value"
        );
    }

    #[test]
    fn a_uuid_inside_quotes_is_not_fragmented_into_hashes() {
        let uuid_input = r#"error "pod 550e8400-e29b-41d4-a716-446655440000 terminated""#;
        let (uuid_result, _) = QuotedStringDetector::detect_and_replace(uuid_input);
        assert_eq!(uuid_result, r#"error "pod <UUID> terminated""#);
        assert!(
            !uuid_result.contains("<HASH>"),
            "UUID should not be fragmented into hashes"
        );
    }

    #[test]
    fn a_url_inside_quotes_is_one_path_not_an_ip() {
        let url_input = r#"error "endpoint http://192.168.1.1:8080/api/v1/users down""#;
        let (url_result, _) = QuotedStringDetector::detect_and_replace(url_input);
        assert_eq!(url_result, r#"error "endpoint <PATH> down""#);
        assert!(
            !url_result.contains("<IP>"),
            "URL should be preserved as complete path"
        );
    }

    #[test]
    fn a_path_a_timestamp_and_a_uuid_in_one_quoted_string_each_fold() {
        let complex_input = r#"error "backup of /data/db at 2025-01-20 10:15:30 for pod 550e8400-e29b-41d4-a716-446655440000 failed""#;
        let (complex_result, _) = QuotedStringDetector::detect_and_replace(complex_input);
        assert_eq!(
            complex_result,
            r#"error "backup of <PATH> at <TIMESTAMP> for pod <UUID> failed""#
        );
    }
}

#[cfg(test)]
mod json_key_veto_edges {
    use super::*;

    #[test]
    fn a_colon_after_optional_blanks_marks_a_key_and_nothing_else_does() {
        assert!(is_json_key(b":v", 0));
        assert!(is_json_key(b"  :v", 0));
        assert!(is_json_key(b"\t:v", 0));
        assert!(!is_json_key(b" v", 0));
        assert!(!is_json_key(b"", 0));
        assert!(!is_json_key(b"x:", 0));
    }

    #[test]
    fn a_quoted_json_key_keeps_its_text_while_its_value_folds() {
        let (out, _) =
            QuotedStringDetector::detect_and_replace(r#""abc123xyz": "some value here""#);
        assert!(out.starts_with(r#""abc123xyz":"#), "{out}");
        let (out, _) =
            QuotedStringDetector::detect_and_replace(r#""abc123xyz" : "some value here""#);
        assert!(out.starts_with(r#""abc123xyz" :"#), "{out}");
        let (plain, _) = QuotedStringDetector::detect_and_replace(r#"saw "abc123xyz" today"#);
        assert!(!plain.contains("abc123xyz"), "{plain}");
    }

    #[test]
    fn an_escaped_blob_in_key_position_still_folds() {
        let (out, _) = QuotedStringDetector::detect_and_replace(r#""a\:b": 1"#);
        assert!(
            out.contains("<ESCAPED_JSON>"),
            "the veto covers the shape fold only; a blob is not a key: {out}"
        );
    }
}
