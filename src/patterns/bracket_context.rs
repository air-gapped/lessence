use super::Token;
use regex::Regex;
use std::sync::LazyLock;

static SINGLE_BRACKET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[([a-zA-Z][a-zA-Z0-9_.-]*)\]").unwrap());

static CHAINED_BRACKET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\[([a-zA-Z][a-zA-Z0-9_.-]*)\]\s*){2,}").unwrap());

pub struct BracketContextDetector;

impl BracketContextDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::contains_bracket_pair(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        Self::apply_chained_bracket_pattern(&mut result, &mut tokens);
        Self::apply_single_bracket_pattern(&mut result, &mut tokens);

        (result, tokens)
    }

    pub(crate) fn contains_bracket_pair(text: &str) -> bool {
        text.contains('[') && text.contains(']')
    }

    fn apply_chained_bracket_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        let folded = CHAINED_BRACKET_REGEX.replace_all(text, |caps: &regex::Captures| {
            Self::fold_context_runs_between_levels(caps.get(0).unwrap().as_str(), tokens)
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *text = s;
        }
    }

    fn fold_context_runs_between_levels(chain: &str, tokens: &mut Vec<Token>) -> String {
        let items: Vec<(usize, &str)> = SINGLE_BRACKET_REGEX
            .captures_iter(chain)
            .map(|c| (c.get(0).unwrap().start(), c.get(1).unwrap().as_str()))
            .collect();
        let bracket_span_through_separator =
            |i: usize| items.get(i + 1).map_or(chain.len(), |next| next.0);
        let mut out = String::with_capacity(chain.len());
        let mut i = 0;
        while i < items.len() {
            if Self::is_level(items[i].1) {
                out.push_str(&chain[items[i].0..bracket_span_through_separator(i)]);
                i += 1;
                continue;
            }
            let mut j = i;
            while j < items.len() && !Self::is_level(items[j].1) {
                j += 1;
            }
            let run = &chain[items[i].0..bracket_span_through_separator(j - 1)];
            let contexts: Vec<String> = items[i..j]
                .iter()
                .map(|(_, ctx)| ctx.to_lowercase())
                .collect();
            if contexts.len() >= 2 && Self::are_logging_contexts(&contexts) {
                tokens.push(Token::BracketContext(contexts));
                let trailing_whitespace = &run[run.trim_end().len()..];
                out.push_str("<BRACKET_CONTEXT>");
                out.push_str(trailing_whitespace);
            } else {
                out.push_str(run);
            }
            i = j;
        }
        out
    }

    fn apply_single_bracket_pattern(text: &mut String, tokens: &mut Vec<Token>) {
        *text = SINGLE_BRACKET_REGEX
            .replace_all(text, |caps: &regex::Captures| {
                let context = caps.get(1).unwrap().as_str();

                if Self::is_logging_context(context) {
                    tokens.push(Token::BracketContext(vec![context.to_lowercase()]));
                    "<BRACKET_CONTEXT>".to_string()
                } else {
                    caps.get(0).unwrap().as_str().to_string()
                }
            })
            .to_string();
    }

    fn is_level(context: &str) -> bool {
        crate::briefing::word_to_level(context.as_bytes()).is_some()
    }

    fn is_logging_context(context: &str) -> bool {
        let lower_context = context.to_lowercase();

        let log_components = [
            "upstream",
            "downstream",
            "proxy",
            "ssl",
            "tls",
            "auth",
            "config",
            "listener",
            "cluster",
            "backend",
            "frontend",
            "handler",
            "worker",
            "manager",
            "service",
            "client",
            "server",
            "connection",
            "request",
            "response",
            "session",
        ];

        let web_modules = [
            "mod_jk",
            "mod_ssl",
            "mod_rewrite",
            "mod_security",
            "mod_proxy",
            "ngx_http",
            "core",
            "main",
            "event",
            "http",
        ];

        let system_contexts = [
            "kernel", "systemd", "init", "cron", "syslog", "audit", "security", "firewall",
            "network", "storage", "memory",
        ];

        log_components.contains(&lower_context.as_str())
            || web_modules.contains(&lower_context.as_str())
            || system_contexts.contains(&lower_context.as_str())
            || lower_context.ends_with("_service")
            || lower_context.ends_with("_manager")
            || lower_context.ends_with("_client")
            || lower_context.ends_with("_server")
            || lower_context.starts_with("mod_")
            || lower_context.starts_with("ngx_")
    }

    fn are_logging_contexts(contexts: &[String]) -> bool {
        contexts.iter().any(|ctx| Self::is_logging_context(ctx))
            && !contexts.iter().any(|ctx| Self::is_non_context_shape(ctx))
    }

    fn is_non_context_shape(ctx: &str) -> bool {
        let all_digits = ctx.chars().all(|c| c.is_ascii_digit());
        let has_colon = ctx.contains(':');
        let one_char = ctx.len() == 1;
        all_digits || has_colon || one_char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chained_brackets_keep_the_space_after_them() {
        let (r, _) =
            BracketContextDetector::detect_and_replace("[proxy] [upstream] OK (DoH) - rtt: 4ms");
        assert_eq!(r, "<BRACKET_CONTEXT> OK (DoH) - rtt: 4ms");
    }

    #[test]
    fn a_bracketed_level_stays_on_the_line() {
        for line in [
            "[error] upstream gone",
            "[info] upstream gone",
            "[NOTICE] upstream gone",
            "[Warning] upstream gone",
            "[debug] upstream gone",
        ] {
            let (r, tokens) = BracketContextDetector::detect_and_replace(line);
            assert_eq!(r, line);
            assert!(tokens.is_empty(), "{line}: {tokens:?}");
        }
    }

    #[test]
    fn a_level_in_a_chain_stays_and_the_context_folds() {
        let (r, tokens) =
            BracketContextDetector::detect_and_replace("[error] [proxy] upstream gone");
        assert_eq!(r, "[error] <BRACKET_CONTEXT> upstream gone");
        assert_eq!(tokens, vec![Token::BracketContext(vec!["proxy".into()])]);

        let (r, tokens) =
            BracketContextDetector::detect_and_replace("[info] [proxy] [upstream] upstream gone");
        assert_eq!(r, "[info] <BRACKET_CONTEXT> upstream gone");
        assert_eq!(
            tokens,
            vec![Token::BracketContext(vec![
                "proxy".into(),
                "upstream".into()
            ])]
        );

        let (r, _) =
            BracketContextDetector::detect_and_replace("[proxy] [error] [upstream] upstream gone");
        assert_eq!(
            r, "<BRACKET_CONTEXT> [error] <BRACKET_CONTEXT> upstream gone",
            "a level between two contexts splits them into two runs of one"
        );

        let (r, tokens) =
            BracketContextDetector::detect_and_replace("[NOTICE] [cloudflare] OK (DoH)");
        assert_eq!(
            r, "[NOTICE] [cloudflare] OK (DoH)",
            "a chain whose only recognised word is the level folds nothing"
        );
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_apache_mod_jk_detection() {
        let apache_line =
            "[Sun Dec 04 04:47:44 2005] [error] [mod_jk] child workerEnv in error state 6";
        let (result, tokens) = BracketContextDetector::detect_and_replace(apache_line);

        assert_eq!(
            result,
            "[Sun Dec 04 04:47:44 2005] [error] <BRACKET_CONTEXT> child workerEnv in error state 6"
        );
        assert_eq!(tokens, vec![Token::BracketContext(vec!["mod_jk".into()])]);
    }

    #[test]
    fn test_envoy_chained_contexts() {
        let envoy_line =
            "envoy[12345] [info] [upstream] [cluster] 'user-service' setting health check";
        let (result, tokens) = BracketContextDetector::detect_and_replace(envoy_line);

        assert_eq!(
            result,
            "envoy[12345] [info] <BRACKET_CONTEXT> 'user-service' setting health check"
        );
        assert_eq!(
            tokens,
            vec![Token::BracketContext(vec![
                "upstream".into(),
                "cluster".into()
            ])]
        );
    }

    #[test]
    fn a_systemd_unit_bracket_is_not_a_context() {
        let systemd_line = "systemd[1]: [info] [unit] Starting network service";
        let (result, tokens) = BracketContextDetector::detect_and_replace(systemd_line);

        assert_eq!(
            result, systemd_line,
            "[info] is a level and [unit] is no context word"
        );
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn test_no_false_positives() {
        let non_logging_cases = vec![
            "Array access array[index] operation",
            "IPv6 address [2001:db8::1]:8080",
            "Math expression [1 + 2] = 3",
            "URL with query params [param=value]",
        ];

        for test_case in non_logging_cases {
            let (result, tokens) = BracketContextDetector::detect_and_replace(test_case);

            assert_eq!(result, test_case);
            assert_eq!(tokens.len(), 0);
        }
    }

    #[test]
    fn only_square_brackets_are_contexts() {
        let mixed_line = "[proxy] Processing (failed) with {result: null}";
        let (result, tokens) = BracketContextDetector::detect_and_replace(mixed_line);

        assert_eq!(
            result,
            "<BRACKET_CONTEXT> Processing (failed) with {result: null}"
        );
        assert_eq!(tokens, vec![Token::BracketContext(vec!["proxy".into()])]);
    }

    #[test]
    fn bracket_ind_requires_open_bracket() {
        assert!(!BracketContextDetector::contains_bracket_pair(
            "error] happened"
        ));
    }

    #[test]
    fn bracket_ind_requires_close_bracket() {
        assert!(!BracketContextDetector::contains_bracket_pair(
            "[error happened"
        ));
    }

    #[test]
    fn bracket_ind_positive() {
        assert!(BracketContextDetector::contains_bracket_pair(
            "[error] happened"
        ));
    }

    #[test]
    fn a_non_context_bracket_does_not_veto_its_line() {
        for (line, folded) in [
            (
                "[proxy] connect [2001:db8::1]:8080",
                "<BRACKET_CONTEXT> connect [2001:db8::1]:8080",
            ),
            (
                "[proxy] data array[0] value",
                "<BRACKET_CONTEXT> data array[0] value",
            ),
            (
                "[proxy] at index[5] pos",
                "<BRACKET_CONTEXT> at index[5] pos",
            ),
            ("[proxy] param=value", "<BRACKET_CONTEXT> param=value"),
            ("[proxy] sum [1 + 2]", "<BRACKET_CONTEXT> sum [1 + 2]"),
            ("[proxy] regex [0-9] x", "<BRACKET_CONTEXT> regex [0-9] x"),
            (
                "[proxy] kubelet started",
                "<BRACKET_CONTEXT> kubelet started",
            ),
        ] {
            assert!(BracketContextDetector::contains_bracket_pair(line));
            assert_eq!(BracketContextDetector::detect_and_replace(line).0, folded);
        }
    }

    #[test]
    fn test_context_classification() {
        assert!(
            !BracketContextDetector::is_logging_context("error"),
            "a level is never a context"
        );
        assert!(
            !BracketContextDetector::is_logging_context("NOTICE"),
            "a level is never a context"
        );
        assert!(BracketContextDetector::is_level("NOTICE"));
        assert!(BracketContextDetector::is_level("err"));
        assert!(!BracketContextDetector::is_level("proxy"));
        assert!(BracketContextDetector::is_logging_context("upstream"));
        assert!(BracketContextDetector::is_logging_context("mod_ssl"));
        assert!(
            !BracketContextDetector::is_logging_context("kubelet"),
            "kubelet is the KubernetesDetector's, not a bracket context"
        );

        assert!(!BracketContextDetector::is_logging_context("123"));
        assert!(!BracketContextDetector::is_logging_context("2001:db8"));
        assert!(!BracketContextDetector::is_logging_context("a"));
    }

    #[test]
    fn logging_ctx_system_context() {
        assert!(BracketContextDetector::is_logging_context("kernel"));
        assert!(BracketContextDetector::is_logging_context("cron"));
        assert!(BracketContextDetector::is_logging_context("firewall"));
    }

    #[test]
    fn logging_ctx_service_suffix() {
        assert!(BracketContextDetector::is_logging_context("app_service"));
    }

    #[test]
    fn logging_ctx_manager_suffix() {
        assert!(BracketContextDetector::is_logging_context("task_manager"));
    }

    #[test]
    fn logging_ctx_client_suffix() {
        assert!(BracketContextDetector::is_logging_context("http_client"));
    }

    #[test]
    fn logging_ctx_server_suffix() {
        assert!(BracketContextDetector::is_logging_context("web_server"));
    }

    #[test]
    fn logging_ctx_mod_prefix() {
        assert!(BracketContextDetector::is_logging_context("mod_proxy"));
    }

    #[test]
    fn logging_ctx_ngx_prefix() {
        assert!(BracketContextDetector::is_logging_context("ngx_http"));
    }

    #[test]
    fn logging_ctx_web_module() {
        assert!(BracketContextDetector::is_logging_context("core"));
        assert!(BracketContextDetector::is_logging_context("event"));
    }

    #[test]
    fn logging_ctx_log_component() {
        assert!(BracketContextDetector::is_logging_context("proxy"));
        assert!(BracketContextDetector::is_logging_context("ssl"));
        assert!(BracketContextDetector::is_logging_context("auth"));
    }

    #[test]
    fn logging_ctx_negative() {
        assert!(!BracketContextDetector::is_logging_context("zzz_random"));
    }

    #[test]
    fn are_logging_ctxs_valid() {
        assert!(BracketContextDetector::are_logging_contexts(&[
            "proxy".to_string()
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_all_digits() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "proxy".to_string(),
            "123".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_colon() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "proxy".to_string(),
            "2001:db8".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_rejects_single_char() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "proxy".to_string(),
            "a".to_string(),
        ]));
    }

    #[test]
    fn are_logging_ctxs_none_recognized() {
        assert!(!BracketContextDetector::are_logging_contexts(&[
            "zzz".to_string()
        ]));
    }

    #[test]
    fn a_single_context_folds_through_the_single_pass() {
        let (result, tokens) =
            BracketContextDetector::detect_and_replace("[proxy] something failed");
        assert!(!tokens.is_empty(), "should detect [proxy]");
        assert!(result.contains("<BRACKET_CONTEXT>"));
        let (_, tokens) = BracketContextDetector::detect_and_replace("[warn] [zzz] [proxy] x");
        assert_eq!(
            tokens,
            vec![Token::BracketContext(vec!["zzz".into(), "proxy".into()])],
            "the run after a level is a chain of its own, one token"
        );
    }

    #[test]
    fn chained_pass_runs_before_single_pass() {
        let line = "[proxy] [upstream] gone";
        let (r, tokens) = BracketContextDetector::detect_and_replace(line);
        assert_eq!(r, "<BRACKET_CONTEXT> gone");
        assert_eq!(
            tokens,
            vec![Token::BracketContext(vec![
                "proxy".into(),
                "upstream".into()
            ])]
        );
        let mut single_first = line.to_string();
        let mut single_tokens = Vec::new();
        BracketContextDetector::apply_single_bracket_pattern(&mut single_first, &mut single_tokens);
        BracketContextDetector::apply_chained_bracket_pattern(
            &mut single_first,
            &mut single_tokens,
        );
        assert_eq!(
            single_first, "<BRACKET_CONTEXT> <BRACKET_CONTEXT> gone",
            "the single pass first folds the chain bracket by bracket"
        );
    }

    #[test]
    fn whole_word_contexts_reject_substrings() {
        for word in ["domain", "remainder", "score", "events"] {
            assert!(!BracketContextDetector::is_logging_context(word), "{word}");
            let line = format!("[{word}] value");
            assert_eq!(BracketContextDetector::detect_and_replace(&line).0, line);
        }
    }

    #[test]
    fn every_word_the_level_statistics_count_stays_literal() {
        for word in [
            "error", "err", "NOTICE", "Warning", "warn", "info", "debug", "fatal",
        ] {
            assert!(
                crate::briefing::word_to_level(word.as_bytes()).is_some(),
                "{word} is a level to the briefing"
            );
            assert!(BracketContextDetector::is_level(word), "{word}");
            let line = format!("[{word}] [proxy] [upstream] x");
            assert_eq!(
                BracketContextDetector::detect_and_replace(&line).0,
                format!("[{word}] <BRACKET_CONTEXT> x"),
                "{word}"
            );
        }
    }

    #[test]
    fn chained_brackets_with_logging_contexts() {
        let (result, tokens) =
            BracketContextDetector::detect_and_replace("[proxy] [upstream] request failed");
        assert!(
            tokens
                .iter()
                .any(|t| if let Token::BracketContext(ctxs) = t {
                    ctxs.len() >= 2
                } else {
                    false
                }),
            "should detect chained contexts: {tokens:?}"
        );
        assert!(result.contains("<BRACKET_CONTEXT>"), "result: {result}");
    }

    #[test]
    fn chained_brackets_non_logging_not_replaced() {
        let input = "[zzz] [qqq] something";
        let (result, tokens) = BracketContextDetector::detect_and_replace(input);
        let chained = tokens.iter().any(|t| {
            if let Token::BracketContext(ctxs) = t {
                ctxs.len() >= 2
            } else {
                false
            }
        });
        assert!(
            !chained,
            "non-logging chains should not be detected: {tokens:?}"
        );
        assert_eq!(result, input);
    }

    #[test]
    fn custom_service_is_a_context_only_by_its_suffix() {
        assert!(BracketContextDetector::is_logging_context("custom_service"));
    }

    #[test]
    fn logging_ctx_manager_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_manager"));
    }

    #[test]
    fn logging_ctx_client_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_client"));
    }

    #[test]
    fn logging_ctx_server_suffix_detected() {
        assert!(BracketContextDetector::is_logging_context("custom_server"));
    }

    #[test]
    fn mod_custom_is_a_context_only_by_its_prefix() {
        assert!(BracketContextDetector::is_logging_context("mod_custom"));
    }

    #[test]
    fn logging_ctx_ngx_prefix_detected() {
        assert!(BracketContextDetector::is_logging_context("ngx_custom"));
    }
}
