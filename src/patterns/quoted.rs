use regex::Regex;
use std::sync::LazyLock;

use super::Token;
use super::{
    duration::DurationDetector, hash::HashDetector, names::NameDetector, network::NetworkDetector,
    path::PathDetector, process::ProcessDetector, timestamp::UnifiedTimestampDetector,
    uuid::UuidDetector,
};

// Match quoted strings that contain variable content, including escaped quotes
// This matches strings like "volume-name", "pod-name", and complex strings with \" inside
// Pattern: " followed by any number of (non-quote OR escaped quote), followed by "
static QUOTED_STRING_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:[^"\\]|\\.)*""#).unwrap());

// A DNS-1123-ish instance identifier standing alone as a whole field value:
// "redis-sentinel-wiki", "iperf3", "argocd/iperf3". Whether such a value
// folds must not depend on how long it happens to be (bead lessence-8jb): the
// 25-char rule below made renaming an app change whether its lines fold.
//
// The leading letter excludes bare numerals and HttpStatusDetector's own bare
// `2xx`/`5xx` output. The class excludes whitespace (prose belongs to the
// length rule), uppercase (enum values like OK/DENIED/StatefulSet) and `<`/`>`
// (placeholders left by the detectors that ran before this one).
static INSTANCE_IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9._/-]*[a-z0-9]$").unwrap());

// Two characters carry no identity worth folding.
const MIN_IDENT_LEN: usize = 3;

// autoresearch: the per-quoted-string cascade below is a pure function of the
// quoted text, so its result can be memoized. Real corpora repeat a small set
// of quoted field names/values millions of times (source 146: ~600k cascade
// calls over a few hundred distinct strings). Thread-local keeps it lock-free
// under rayon; the size/length caps bound memory on adversarial input.
const QUOTED_CACHE_MAX_ENTRIES: usize = 8192;
const QUOTED_CACHE_MAX_KEY_LEN: usize = 256;

thread_local! {
    static QUOTED_CACHE: std::cell::RefCell<std::collections::HashMap<String, QuotedOutcome>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The verdict for one quoted string: the replacement text, whether a
/// `QuotedString` token is emitted, and whether the verdict came from the
/// instance-identifier shape rule (which is vetoed in JSON key position).
type QuotedOutcome = (String, bool, bool);

pub struct QuotedStringDetector;

/// Is the quoted string at `end` a JSON key? A key is followed by `:`, with
/// optional whitespace first — `"k":v` and `"k": v` are both JSON.
fn followed_by_colon(bytes: &[u8], mut at: usize) -> bool {
    while let Some(b) = bytes.get(at) {
        match b {
            b' ' | b'\t' => at += 1,
            b':' => return true,
            _ => return false,
        }
    }
    false
}

impl QuotedStringDetector {
    /// Detect and replace quoted strings that appear to be variables
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no quoted strings
        if !text.contains('"') {
            return (text.to_string(), Vec::new());
        }
        let haystack = text.to_string();
        let mut tokens = Vec::new();

        // Replace all variable quoted strings with placeholder in one pass
        let result = QUOTED_STRING_PATTERN
            .replace_all(&haystack, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap();
                let quoted_string = matched.as_str();

                let cacheable = quoted_string.len() <= QUOTED_CACHE_MAX_KEY_LEN;
                let cached = if cacheable {
                    QUOTED_CACHE.with(|c| c.borrow().get(quoted_string).cloned())
                } else {
                    None
                };

                let (replacement, had_token, shape_folded) = if let Some(outcome) = cached {
                    outcome
                } else {
                    let outcome = Self::normalize_quoted(quoted_string);
                    if cacheable {
                        QUOTED_CACHE.with(|c| {
                            let mut cache = c.borrow_mut();
                            if cache.len() < QUOTED_CACHE_MAX_ENTRIES {
                                cache.insert(quoted_string.to_string(), outcome.clone());
                            }
                        });
                    }
                    outcome
                };

                // A JSON key looks like any other quoted string — there is no
                // way to tell `"app-namespace"` from `"redis-sentinel"`, or a
                // 30-char key from a 30-char message, by the string alone. One
                // lookahead settles it: a key is followed by `:`. A key that
                // folds erases the record's schema from the template, whichever
                // rule folded it, so the veto covers every whole-string
                // replacement — but not a key an inner detector rewrote, which
                // keeps its quotes and its shape.
                let whole_replacement = had_token && replacement == "<QUOTED_STRING>";
                if (shape_folded || whole_replacement)
                    && followed_by_colon(haystack.as_bytes(), matched.end())
                {
                    return quoted_string.to_string();
                }

                if had_token {
                    tokens.push(Token::QuotedString(quoted_string.to_string()));
                }
                replacement
            })
            .to_string();

        (result, tokens)
    }

    /// Whole-value instance identifier: a DNS-1123-ish label standing alone as
    /// a field value. See [`INSTANCE_IDENT`] for why each condition is there.
    fn is_instance_ident(content: &str) -> bool {
        content.len() >= MIN_IDENT_LEN
            && content.bytes().any(|b| b == b'-' || b.is_ascii_digit())
            && INSTANCE_IDENT.is_match(content)
    }

    /// The full normalization cascade for one quoted string (quotes included).
    fn normalize_quoted(quoted_string: &str) -> QuotedOutcome {
        // Normalize patterns WITHIN the quoted content before deciding
        let quoted_content = &quoted_string[1..quoted_string.len() - 1]; // Remove quotes
        let mut normalized_content = quoted_content.to_string();

        // Apply EXACT same pattern detection order as main pipeline
        // This ensures consistency and prevents order-dependent bugs

        // 1. TIMESTAMPS (highest priority - most specific format)
        let (new_normalized, _) = UnifiedTimestampDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 2. PATHS (including full URLs - must run early to preserve URL structure)
        let (new_normalized, _) = PathDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 3. UUIDs (MUST run BEFORE hashes to prevent UUID fragmentation!)
        let (new_normalized, _) = UuidDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 4. NETWORK patterns (IPs, ports, FQDNs)
        let (new_normalized, _) =
            NetworkDetector::detect_and_replace(&normalized_content, true, true, true);
        normalized_content = new_normalized;

        // 5. HASHES (must run AFTER UUIDs)
        let (new_normalized, _) = HashDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 6. PROCESS IDs
        let (new_normalized, _) = ProcessDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 7. DURATIONS & measurements (including integers)
        let (new_normalized, _) = DurationDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // 8. NAMES (hyphenated component names - generic patterns last)
        let (new_normalized, _) = NameDetector::detect_and_replace(&normalized_content);
        normalized_content = new_normalized;

        // Check for escaped JSON FIRST (highest priority)
        if quoted_content.contains('\\')
            && (quoted_content.contains(':')
                || quoted_content.contains('{')
                || quoted_content.contains('['))
        {
            // This is escaped JSON or structured data - normalize it
            ("<ESCAPED_JSON>".to_string(), true, false)
        } else if normalized_content != quoted_content || quoted_content.contains('<') {
            // The content carries variable patterns: either the inner cascade
            // just found them, or — far more often, since this detector runs
            // last — the main pipeline already replaced them with `<TOKEN>`
            // placeholders before we got here. Either way the variable parts
            // are tokenised and the words around them ARE the template. Keep
            // it quoted with the placeholders in place.
            (format!("\"{normalized_content}\""), true, false)
        } else if Self::is_instance_ident(quoted_content) {
            // An instance name — folds on its shape, at any length.
            ("<QUOTED_STRING>".to_string(), true, true)
        } else {
            // Nothing variable inside and no identifier shape. A sentence
            // ("Loading TLS configuration from secret") is the event, not a
            // value of it — two different sentences are two different events
            // however long they are, so it stays literal exactly as an
            // unquoted sentence would. Length used to decide here, and on a
            // JSON `msg` that folded 98.5% of a 60,849-line log into one group
            // (lessence-7lj).
            (quoted_string.to_string(), false, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_operation_quoted_strings() {
        let input = r#"operationExecutor.VerifyControllerAttachedVolume started for volume "csi-log" (UniqueName: "kubernetes.io/host-path/01af48d9-3471-4acf-93aa-689c01b31dff-csi-log") pod "csi-rbdplugin-sr56f" (UID: "01af48d9-3471-4acf-93aa-689c01b31dff")"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // "csi-log" is a whole-value instance identifier (hyphen, no
        // whitespace), so it folds on its shape regardless of length. The
        // other 3 quoted strings have internal patterns that get normalized.
        assert_eq!(tokens.len(), 4);

        // Verify normalized output contains expected patterns
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
    fn test_exclude_keywords() {
        let input = r#"status "started" and "finished" operations"#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // Should not detect keyword strings
        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input); // Unchanged
    }

    #[test]
    fn test_exclude_short_strings() {
        let input = r#"value "x" and "ab" but "plain""#;

        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(input);

        // Below MIN_IDENT_LEN, and a bare word carries no identifier shape, so
        // none of these fold.
        assert_eq!(tokens.len(), 0);
        assert_eq!(normalized, input);
    }

    #[test]
    fn test_duration_normalization_in_quotes() {
        let input1 = r#"error "back-off 5m0s restarting failed""#;
        let input2 = r#"error "back-off 10m0s restarting failed""#;

        let (normalized1, tokens1) = QuotedStringDetector::detect_and_replace(input1);
        let (normalized2, tokens2) = QuotedStringDetector::detect_and_replace(input2);

        // Both should normalize to the same pattern since they only differ in duration
        assert_eq!(normalized1, normalized2);
        assert_eq!(
            normalized1,
            r#"error "back-off <DURATION> restarting failed""#
        );

        // Both should detect tokens
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
    fn test_comprehensive_pattern_grouping() {
        // Test that patterns with different internal variables normalize to the same result
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

        // All should normalize to the same pattern
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
            // Windows paths with backslashes trigger the escaped JSON detection
            // (content has both '\' and ':' which matches the escaped JSON heuristic)
            (
                r#"error "path C:\Windows\System32\config invalid""#,
                r"error <ESCAPED_JSON>",
            ),
        ];

        for (input, expected) in test_cases {
            let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
            assert_eq!(tokens.len(), 1);
        }
    }

    // ---- Mutant-killing: boundary conditions on quote detection ----

    #[test]
    fn quoted_string_escaped_json_bracket_only() {
        // Kills mutant: `|| with &&` on line 78 (contains('['))
        // Input has backslash + bracket but NOT colon and NOT brace
        let input = r#"data "value\[index\]more" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+bracket should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_colon_only() {
        // Input has backslash + colon but NOT brace and NOT bracket
        let input = r#"data "key\:value\:end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+colon should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    #[test]
    fn quoted_string_escaped_json_brace_only() {
        // Input has backslash + brace but NOT colon and NOT bracket
        let input = r#"data "obj\{inner\}end" done"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert!(
            result.contains("<ESCAPED_JSON>"),
            "backslash+brace should trigger escaped JSON: {result}, tokens: {tokens:?}"
        );
    }

    // ---- instance-identifier shape rule (bead lessence-8jb) ----

    /// Fold one quoted string in value position and return the result.
    fn fold_value(value: &str) -> String {
        let (normalized, _) =
            QuotedStringDetector::detect_and_replace(&format!(r#"{{"k":"{value}"}}"#));
        normalized
    }

    #[test]
    fn shape_fold_is_length_independent_bead_8jb() {
        // The bead's repro: five application names spanning the old 25-char
        // boundary. Whether they fold must not depend on how long they are.
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
                "{value} should fold on its shape"
            );
        }
    }

    #[test]
    fn shape_requires_hyphen_or_digit() {
        // A bare lowercase word is shape-identical to an enum value such as a
        // log level, so it stays literal. Each disjunct tested alone.
        assert_eq!(fold_value("harbor"), r#"{"k":"harbor"}"#);
        assert_eq!(fold_value("rook-ceph"), r#"{"k":<QUOTED_STRING>}"#);
        assert_eq!(fold_value("iperf3"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_requires_leading_letter() {
        // HttpStatusDetector emits a bare `2xx`, not an angle-bracket
        // placeholder. A leading digit must not be eaten, or 2xx merges with
        // 5xx.
        assert_eq!(fold_value("2xx"), r#"{"k":"2xx"}"#);
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
        // Prose stays with the length rule. This value is under 25 chars, so
        // the length rule cannot mask a shape-rule mistake.
        assert_eq!(fold_value("Update ok-1"), r#"{"k":"Update ok-1"}"#);
    }

    #[test]
    fn shape_rejects_uppercase() {
        assert_eq!(fold_value("InfoRefs-Pack"), r#"{"k":"InfoRefs-Pack"}"#);
    }

    #[test]
    fn shape_accepts_slash_for_qualified_names() {
        // argocd emits "app-qualified-name":"argocd/iperf3"; without `/` in
        // the class those lines refuse to merge.
        assert_eq!(fold_value("argocd/iperf3"), r#"{"k":<QUOTED_STRING>}"#);
    }

    #[test]
    fn shape_rejects_empty_value() {
        let (normalized, tokens) = QuotedStringDetector::detect_and_replace(r#"{"k":""}"#);
        assert_eq!(normalized, r#"{"k":""}"#);
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn shape_vetoed_when_the_string_is_a_json_key() {
        // A key has the same shape as an instance name. Folding it would erase
        // the record's schema from the template.
        let (normalized, _) =
            QuotedStringDetector::detect_and_replace(r#"{"app-namespace":"argocd"}"#);
        assert_eq!(normalized, r#"{"app-namespace":"argocd"}"#);
    }

    #[test]
    fn shape_not_vetoed_for_the_same_string_in_value_position() {
        // Paired with the veto test above: together they prove the veto is
        // positional and is not baked into the memo cache.
        assert_eq!(fold_value("app-namespace"), r#"{"k":<QUOTED_STRING>}"#);
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
        // The inner cascade already recognised something here; the shape rule
        // must not run ahead of it and throw that away.
        let normalized = fold_value("v1.31.4");
        assert!(
            !normalized.contains("<QUOTED_STRING>"),
            "claimed content must keep its normalized form: {normalized}"
        );
        assert!(normalized.contains("<DECIMAL>"), "{normalized}");
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
        // lessence-7lj: length used to decide here (> 25 chars -> folded).
        // A sentence with nothing variable inside IS the event; two different
        // sentences are two events at any length.
        for content in [
            "it is a very simple tex",            // 23 chars, under the old floor
            "it is a very simple text",           // 24 — the old boundary
            "it is a very simple text indeed ok", // well over
        ] {
            let input = format!(r#"x "{content}""#);
            let (result, tokens) = QuotedStringDetector::detect_and_replace(&input);
            assert_eq!(result, input, "prose must survive verbatim");
            assert!(tokens.is_empty(), "prose emits no token: {tokens:?}");
        }
    }

    #[test]
    fn a_quoted_sentence_keeps_placeholders_the_pipeline_already_put_in_it() {
        // This detector runs last. By then the main pipeline has replaced the
        // variable parts with <TOKEN>s; the inner cascade then finds nothing
        // left to change. That must count as "claimed", not fall through to
        // the prose branch — the words around the placeholders are the template.
        let input = r#"{"msg":"Refreshing app status (expiry: <DURATION>), level (2)"}"#;
        let (result, tokens) = QuotedStringDetector::detect_and_replace(input);
        assert_eq!(result, input);
        assert_eq!(
            tokens.len(),
            1,
            "one QuotedString token for the claimed value"
        );
    }

    #[test]
    fn test_order_critical_patterns() {
        // Test UUID detection happens before hash detection
        let uuid_input = r#"error "pod 550e8400-e29b-41d4-a716-446655440000 terminated""#;
        let (uuid_result, _) = QuotedStringDetector::detect_and_replace(uuid_input);
        assert_eq!(uuid_result, r#"error "pod <UUID> terminated""#);
        assert!(
            !uuid_result.contains("<HASH>"),
            "UUID should not be fragmented into hashes"
        );

        // Test URL paths are preserved (path detection before network)
        let url_input = r#"error "endpoint http://192.168.1.1:8080/api/v1/users down""#;
        let (url_result, _) = QuotedStringDetector::detect_and_replace(url_input);
        assert_eq!(url_result, r#"error "endpoint <PATH> down""#);
        assert!(
            !url_result.contains("<IP>"),
            "URL should be preserved as complete path"
        );

        // Test complex pattern with multiple types
        let complex_input = r#"error "backup of /data/db at 2025-01-20 10:15:30 for pod 550e8400-e29b-41d4-a716-446655440000 failed""#;
        let (complex_result, _) = QuotedStringDetector::detect_and_replace(complex_input);
        assert_eq!(
            complex_result,
            r#"error "backup of <PATH> at <TIMESTAMP> for pod <UUID> failed""#
        );
    }
}
