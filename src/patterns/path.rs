use regex::Regex;
use std::sync::LazyLock;

use super::Token;

const PATH_SEGMENT_CHAR: &str = r"a-zA-Z0-9_.\-~";

static FILE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(/[{PATH_SEGMENT_CHAR}/]+(?:\.[a-zA-Z0-9]+)?(?:/[{PATH_SEGMENT_CHAR}]*)*/?)"
    ))
    .expect("Failed to compile file path regex")
});

static RELATIVE_PATH_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\b[a-zA-Z0-9_\-]+(?:/[{PATH_SEGMENT_CHAR}]+)+\b"))
        .expect("Failed to compile relative path regex")
});

static URL_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"((?:/[a-zA-Z0-9_.\-~%]*)+(?:\?[a-zA-Z0-9_.\-~%&=]*)?(?:#[a-zA-Z0-9_.\-~%]*)?)")
        .expect("Failed to compile URL path regex")
});

static FULL_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^/\s"]+(?:/[^\s"]*)?"#).expect("Failed to compile full URL regex")
});

const SENTENCE_PUNCTUATION_AFTER_A_URL: [char; 6] = [')', ']', ',', '.', ';', '\''];

static WINDOWS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z]:\\[a-zA-Z0-9_.\-\\]+(?:\\[a-zA-Z0-9_.\-]*)*\\?)")
        .expect("Failed to compile Windows path regex")
});

static QUERY_PARAMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\?([a-zA-Z0-9_\-]+=([^&\s]+)(&[a-zA-Z0-9_\-]+=([^&\s]+))*)")
        .expect("Failed to compile query params regex")
});

const HEX_ID_SEGMENT: &str = "[0-9a-fA-F]{8,}";
const NUMERIC_ID_SEGMENT: &str = "[0-9]{3,}";
const HEX_AND_DASH_ID_SEGMENT: &str = r"[a-fA-F0-9\-]{8,}";

static GENERATED_ID_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        "/({HEX_ID_SEGMENT}|{NUMERIC_ID_SEGMENT}|{HEX_AND_DASH_ID_SEGMENT})"
    ))
    .expect("Failed to compile route params regex")
});

static URL_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/([a-zA-Z0-9][a-zA-Z0-9\-]{2,}[a-zA-Z0-9])")
        .expect("Failed to compile path segments regex")
});

static SOURCE_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"([a-zA-Z_][a-zA-Z0-9_\-]*\.({})):\d+\]",
        super::SOURCE_EXTENSIONS.join("|")
    ))
    .expect("Failed to compile source line regex")
});

static SYSLOG_PROGRAM_TAG_WRITTEN_AS_A_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(/[A-Za-z0-9_./~-]+)\[\d+\]:").expect("Failed to compile syslog path tag regex")
});

const MIN_FILE_PATH_LEN: usize = 3;

#[derive(Clone, Copy, Debug)]
struct SyslogProgramTag {
    start: usize,
    end: usize,
}

impl SyslogProgramTag {
    fn overlaps(self, m: &regex::Match) -> bool {
        m.start() < self.end && m.end() > self.start
    }
}

type PathPass = fn(&mut String, &mut Vec<Token>, Option<SyslogProgramTag>);

pub struct PathDetector;

impl PathDetector {
    const PASSES_FULL_URL_BEFORE_FILE_PATH: [PathPass; 6] = [
        Self::fold_source_line_numbers,
        Self::fold_full_urls,
        Self::fold_file_paths,
        Self::fold_relative_paths,
        Self::fold_windows_paths,
        Self::fold_url_paths,
    ];

    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        Self::detect_and_replace_with(text, true)
    }

    pub fn detect_and_replace_with(text: &str, event_objects: bool) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();
        let tag = Self::syslog_program_tag_span(text);
        if event_objects {
            Self::fold_event_object_meta(&mut result, &mut tokens, tag);
        }
        for pass in Self::PASSES_FULL_URL_BEFORE_FILE_PATH {
            let tag_now = tag.and_then(|_| Self::syslog_program_tag_span(&result));
            pass(&mut result, &mut tokens, tag_now);
        }
        (result, tokens)
    }

    fn fold_event_object_meta(
        result: &mut String,
        tokens: &mut Vec<Token>,
        _: Option<SyslogProgramTag>,
    ) {
        let folded = super::EVENT_OBJECT_META.replace_all(result, |caps: &regex::Captures| {
            let event = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(event.to_string()));
            "<EVENT_OBJECT>".to_string()
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_source_line_numbers(
        result: &mut String,
        tokens: &mut Vec<Token>,
        _: Option<SyslogProgramTag>,
    ) {
        let folded = SOURCE_LINE.replace_all(result, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let filename = caps.get(1).unwrap().as_str();
            tokens.push(Token::Path(matched.to_string()));
            format!("{filename}:<LINE>]")
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_full_urls(result: &mut String, tokens: &mut Vec<Token>, _: Option<SyslogProgramTag>) {
        let folded = FULL_URL.replace_all(result, |caps: &regex::Captures| {
            let whole = caps.get(0).unwrap().as_str();
            let url = whole
                .trim_end_matches(SENTENCE_PUNCTUATION_AFTER_A_URL)
                .trim_end_matches('\\');
            tokens.push(Token::Path(url.to_string()));
            format!("<PATH>{}", &whole[url.len()..])
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_file_paths(
        result: &mut String,
        tokens: &mut Vec<Token>,
        tag: Option<SyslogProgramTag>,
    ) {
        let folded = FILE_PATH.replace_all(result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            if Self::is_likely_file_path(path)
                && !Self::is_glued_to_word(result, &caps.get(0).unwrap())
                && !Self::in_syslog_tag(tag, &caps.get(0).unwrap())
            {
                tokens.push(Token::Path(path.to_string()));
                "<PATH>".to_string()
            } else {
                caps[0].to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_relative_paths(
        result: &mut String,
        tokens: &mut Vec<Token>,
        tag: Option<SyslogProgramTag>,
    ) {
        if !result.contains('/') {
            return;
        }
        let folded = RELATIVE_PATH_CANDIDATE.replace_all(result, |caps: &regex::Captures| {
            let m = caps.get(0).unwrap();
            if Self::is_relative_path(result, &m) && !Self::in_syslog_tag(tag, &m) {
                tokens.push(Token::Path(m.as_str().to_string()));
                "<PATH>".to_string()
            } else {
                m.as_str().to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_windows_paths(
        result: &mut String,
        tokens: &mut Vec<Token>,
        _: Option<SyslogProgramTag>,
    ) {
        let folded = WINDOWS_PATH.replace_all(result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            tokens.push(Token::Path(path.to_string()));
            "<PATH>".to_string()
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_url_paths(result: &mut String, tokens: &mut Vec<Token>, tag: Option<SyslogProgramTag>) {
        let folded = URL_PATH.replace_all(result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            if Self::is_likely_url_path(path)
                && !Self::is_glued_to_word(result, &caps.get(0).unwrap())
                && !Self::in_syslog_tag(tag, &caps.get(0).unwrap())
            {
                let normalized = Self::normalize_url_path(path);
                tokens.push(Token::Path(path.to_string()));
                normalized
            } else {
                caps[0].to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn has_multiple_segments(path: &str) -> bool {
        path.matches('/').count() > 1
    }

    fn is_likely_file_path(path: &str) -> bool {
        let last_segment_has_extension = path.split('/').next_back().unwrap_or("").contains('.');
        path.starts_with('/')
            && path.len() >= MIN_FILE_PATH_LEN
            && (last_segment_has_extension || Self::has_multiple_segments(path))
    }

    fn syslog_program_tag_span(text: &str) -> Option<SyslogProgramTag> {
        let caps = SYSLOG_PROGRAM_TAG_WRITTEN_AS_A_PATH.captures(text)?;
        let m = caps.get(1)?;
        Some(SyslogProgramTag {
            start: m.start(),
            end: m.end(),
        })
    }

    fn in_syslog_tag(tag: Option<SyslogProgramTag>, m: &regex::Match) -> bool {
        tag.is_some_and(|t| t.overlaps(m))
    }

    fn is_glued_to_word(haystack: &str, m: &regex::Match) -> bool {
        m.start() > 0 && haystack.as_bytes()[m.start() - 1].is_ascii_alphanumeric()
    }

    fn is_relative_path(haystack: &str, m: &regex::Match) -> bool {
        let continues_a_dotted_name =
            m.start() > 0 && matches!(haystack.as_bytes()[m.start() - 1], b'.' | b'/' | b'\\');
        let path = m.as_str();
        let rest = &path[path.find('/').unwrap_or(0)..];
        let is_version_or_hex_pair = rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b'/');
        let two_segments_or_a_file =
            rest[1..].contains('/') || rest.rsplit('/').next().unwrap_or("").contains('.');
        !continues_a_dotted_name && !is_version_or_hex_pair && two_segments_or_a_file
    }

    fn is_likely_url_path(path: &str) -> bool {
        path.starts_with('/')
            && (path.contains('?')
                || Self::has_multiple_segments(path)
                || GENERATED_ID_SEGMENT.is_match(path))
    }

    fn is_generated_segment(segment: &str) -> bool {
        segment.bytes().any(|b| b.is_ascii_digit())
    }

    fn normalize_url_path(path: &str) -> String {
        let mut normalized = GENERATED_ID_SEGMENT
            .replace_all(path, "/<PATH>")
            .to_string();

        normalized = URL_SEGMENT
            .replace_all(&normalized, |caps: &regex::Captures| {
                let segment = caps.get(1).unwrap().as_str();
                if Self::is_generated_segment(segment) {
                    "/<PATH>".to_string()
                } else {
                    format!("/{segment}")
                }
            })
            .to_string();

        normalized = QUERY_PARAMS
            .replace_all(&normalized, |caps: &regex::Captures| {
                let full_query = caps.get(1).unwrap().as_str();
                let parts: Vec<&str> = full_query.split('&').collect();
                let normalized_parts: Vec<String> = parts
                    .iter()
                    .map(|part| {
                        if let Some(eq_pos) = part.find('=') {
                            format!("{}=<PATH>", &part[..eq_pos])
                        } else {
                            part.to_string()
                        }
                    })
                    .collect();
                format!("?{}", normalized_parts.join("&"))
            })
            .to_string();

        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_object_dump_folds_to_one_placeholder() {
        let (result, tokens) =
            PathDetector::detect_and_replace("got &Event{ObjectMeta:{name:a ns:{b}}} done");
        assert_eq!(result, "got <EVENT_OBJECT>} done");
        assert_eq!(tokens.len(), 1, "{tokens:?}");
    }

    #[test]
    fn test_file_path_detection() {
        let test_cases = vec![
            ("/var/log/app.log", true),
            ("/home/user/document.txt", true),
            ("/usr/bin/python", true),
            ("/", false),
            ("/a", false),
            ("not/a/path", false),
        ];

        for (path, expected) in test_cases {
            assert_eq!(
                PathDetector::is_likely_file_path(path),
                expected,
                "Failed for path: {path}"
            );
        }
    }

    #[test]
    fn test_url_path_detection() {
        let test_cases = vec![
            ("/api/users/123", true),
            ("/static/css/main.css", true),
            ("/search?q=test", true),
            ("/", false),
            ("/a", false),
        ];

        for (path, expected) in test_cases {
            assert_eq!(
                PathDetector::is_likely_url_path(path),
                expected,
                "Failed for path: {path}"
            );
        }
    }

    #[test]
    fn a_path_under_min_file_path_len_is_rejected() {
        for (path, case) in [
            ("/a", "file_path_short_rejected"),
            ("/a", "file_path_len_under_3"),
            ("/a", "file_path_len_exactly_2_rejected"),
            ("/.", "two bytes with an extension dot"),
            ("//", "two bytes with two slashes"),
        ] {
            assert!(
                !PathDetector::is_likely_file_path(path),
                "{case}: {path} is under MIN_FILE_PATH_LEN"
            );
        }
    }

    #[test]
    fn a_file_path_needs_a_leading_slash() {
        for (path, case) in [
            ("var/log", "file_path_no_leading_slash_rejected"),
            ("no_slash", "file_path_no_leading_slash"),
        ] {
            assert!(!PathDetector::is_likely_file_path(path), "{case}: {path}");
        }
    }

    #[test]
    fn file_path_common_dir() {
        assert!(PathDetector::is_likely_file_path("/var/log"));
    }

    #[test]
    fn file_path_with_extension() {
        assert!(PathDetector::is_likely_file_path("/app/main.rs"));
    }

    #[test]
    fn url_path_api_pattern() {
        assert!(PathDetector::is_likely_url_path("/api/v1/users"));
    }

    #[test]
    fn a_bare_slash_is_not_a_url_path() {
        for case in [
            "url_path_too_short",
            "url_path_len_under_2",
            "url_path_len_exactly_1_rejected",
        ] {
            assert!(
                !PathDetector::is_likely_url_path("/"),
                "{case}: one slash, no query, no id segment"
            );
        }
    }

    #[test]
    fn url_path_query_params() {
        assert!(PathDetector::is_likely_url_path("/search?q=test"));
    }

    #[test]
    fn test_path_normalization() {
        let test_cases = vec![
            ("Error in /var/log/app.2025-01-20.log", "Error in <PATH>"),
            ("GET /api/users/123/posts", "GET <PATH>"),
            (r"C:\Users\john\Documents\file.txt", "<PATH>"),
        ];

        for (input, expected) in test_cases {
            let (result, _tokens) = PathDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
        }
    }

    #[test]
    fn a_route_word_stays_while_query_values_fold() {
        let (result, _) = PathDetector::detect_and_replace("Request to /search?q=test&page=5");
        assert_eq!(
            result, "Request to /search?q=<PATH>&page=<PATH>",
            "`search` is a route word and stays; each query value folds"
        );
    }

    #[test]
    fn file_path_has_extension() {
        assert!(PathDetector::is_likely_file_path("/app.log"));
    }

    #[test]
    fn file_path_multiple_segments() {
        assert!(PathDetector::is_likely_file_path("/usr/bin/python"));
    }

    #[test]
    fn file_path_var() {
        assert!(PathDetector::is_likely_file_path("/var/log/syslog"));
    }

    #[test]
    fn file_path_usr() {
        assert!(PathDetector::is_likely_file_path("/usr/local/bin"));
    }

    #[test]
    fn file_path_etc() {
        assert!(PathDetector::is_likely_file_path("/etc/nginx/nginx.conf"));
    }

    #[test]
    fn file_path_home() {
        assert!(PathDetector::is_likely_file_path("/home/user/doc"));
    }

    #[test]
    fn file_path_opt() {
        assert!(PathDetector::is_likely_file_path("/opt/app/bin"));
    }

    #[test]
    fn file_path_tmp() {
        assert!(PathDetector::is_likely_file_path("/tmp/data"));
    }

    #[test]
    fn url_path_no_leading_slash() {
        assert!(!PathDetector::is_likely_url_path("api/v1"));
    }

    #[test]
    fn url_path_api() {
        assert!(PathDetector::is_likely_url_path("/api/users"));
    }

    #[test]
    fn url_path_v1() {
        assert!(PathDetector::is_likely_url_path("/v1/resources"));
    }

    #[test]
    fn url_path_v2() {
        assert!(PathDetector::is_likely_url_path("/v2/items"));
    }

    #[test]
    fn url_path_static() {
        assert!(PathDetector::is_likely_url_path("/static/style.css"));
    }

    #[test]
    fn url_path_assets() {
        assert!(PathDetector::is_likely_url_path("/assets/img.png"));
    }

    #[test]
    fn url_path_has_query_params() {
        assert!(PathDetector::is_likely_url_path("/search?q=test"));
    }

    #[test]
    fn url_path_multi_segments() {
        assert!(PathDetector::is_likely_url_path("/users/123/orders"));
    }

    #[test]
    fn a_three_byte_path_passes_the_length_floor() {
        assert!(PathDetector::is_likely_file_path("/a."));
    }

    #[test]
    fn file_path_has_extension_only() {
        assert!(
            PathDetector::is_likely_file_path("/x.log"),
            "one slash, so only the extension holds"
        );
    }

    #[test]
    fn file_path_has_multiple_segments_only() {
        assert!(PathDetector::is_likely_file_path("/foo/bar/baz"));
    }

    #[test]
    fn a_common_unix_dir_is_a_path_by_its_two_slashes() {
        assert!(
            PathDetector::is_likely_file_path("/var/x"),
            "no extension: the two slashes alone make it a path"
        );
    }

    #[test]
    fn file_path_none_of_three_conditions() {
        assert!(
            !PathDetector::is_likely_file_path("/xyz"),
            "no extension and one slash"
        );
    }

    #[test]
    fn a_bare_query_mark_is_a_url_path() {
        assert!(PathDetector::is_likely_url_path("/?"));
    }

    #[test]
    fn url_path_api_prefix_with_two_segments() {
        assert!(
            PathDetector::is_likely_url_path("/v1/items"),
            "an API prefix always brings a second slash"
        );
    }

    #[test]
    fn url_path_has_query_params_only() {
        assert!(
            PathDetector::is_likely_url_path("/x?q=1"),
            "one slash, no id segment: only the query holds"
        );
    }

    #[test]
    fn url_path_has_multiple_segments_only() {
        assert!(
            PathDetector::is_likely_url_path("/foo/bar"),
            "no query, no id segment: only the second slash holds"
        );
    }

    #[test]
    fn url_path_has_numeric_ids_only() {
        assert!(
            PathDetector::is_likely_url_path("/12345"),
            "one slash, no query: only the generated id segment holds"
        );
    }

    #[test]
    fn url_path_segment_count_boundary() {
        assert!(!PathDetector::is_likely_url_path("/x"), "one slash");
        assert!(PathDetector::is_likely_url_path("/x/y"), "two slashes");
    }

    #[test]
    fn a_digit_bearing_segment_folds_and_a_word_segment_stays() {
        let result = PathDetector::normalize_url_path("/namespaces/my-ns/pods/nginx-7d9f8");
        assert_eq!(result, "/namespaces/my-ns/pods/<PATH>");
        assert_eq!(
            PathDetector::normalize_url_path("/login?next=home"),
            "/login?next=<PATH>"
        );
        assert_ne!(
            PathDetector::normalize_url_path("/login"),
            PathDetector::normalize_url_path("/logout")
        );
    }

    #[test]
    fn normalize_url_path_static_preserved() {
        let result = PathDetector::normalize_url_path("/static/style.css");
        assert!(
            result.contains("/static"),
            "static should be preserved, got: {result}"
        );
    }

    #[test]
    fn normalize_url_path_health_preserved() {
        let result = PathDetector::normalize_url_path("/health/check-endpoint");
        assert!(
            result.contains("/health"),
            "health should be preserved, got: {result}"
        );
    }

    #[test]
    fn a_slash_glued_to_a_word_is_not_a_path() {
        for (input, expected) in [
            ("HTTP/1.1 x", "HTTP/1.1 x"),
            ("curl/7.68.0 x", "curl/7.68.0 x"),
            ("LSN 6E/F9009520 x", "LSN 6E/F9009520 x"),
            (
                "key feature.node.kubernetes.io/cpu-cpuid.X87=true",
                "key feature.node.kubernetes.io/cpu-cpuid.X87=true",
            ),
            (
                "image docker.io/library/nginx:1.25 x",
                "image docker.io/library/nginx:1.25 x",
            ),
            ("dial http://0.0.0.0 x", "dial <PATH> x"),
            ("file=/var/log/app.log x", "file=<PATH> x"),
            ("read /etc/hosts.d/x x", "read <PATH> x"),
        ] {
            let (r, _) = PathDetector::detect_and_replace(input);
            assert_eq!(
                r, expected,
                "a slash glued to a word continues it; a bare URL or a path after a separator is still a path: {input}"
            );
        }
    }

    #[test]
    fn a_url_does_not_swallow_the_closing_bracket() {
        let (r, _) =
            PathDetector::detect_and_replace("Unreachable (http://unifi:8080/inform) rc=3");
        assert_eq!(r, "Unreachable (<PATH>) rc=3");
        let (r, _) = PathDetector::detect_and_replace("see https://example.com/a/b. Then");
        assert_eq!(r, "see <PATH>. Then");
    }

    #[test]
    fn a_url_inside_an_escaped_string_leaves_the_escaped_quote_whole() {
        let (r, tokens) = PathDetector::detect_and_replace(
            r#"{"error":"Get \"https://h.example:443/a?b=1\": dial"}"#,
        );
        assert_eq!(r, r#"{"error":"Get \"<PATH>\": dial"}"#);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Path(url) if url == "https://h.example:443/a?b=1")),
            "{tokens:?}"
        );
    }

    #[test]
    fn a_relative_path_is_a_path() {
        for (input, expected) in [
            ("at internal/pkg/x.go:45 x", "at <PATH>:45 x"),
            ("resource=netpol/argocd/argocd-redis x", "resource=<PATH> x"),
            ("in pkg/x.go x", "in <PATH> x"),
            ("type text/html x", "type text/html x"),
            ("agent Mozilla/5.0 x", "agent Mozilla/5.0 x"),
            (
                "pod kube-system/coredns-abc x",
                "pod kube-system/coredns-abc x",
            ),
            (
                "image docker.io/library/nginx x",
                "image docker.io/library/nginx x",
            ),
            (
                "at github.com/foo/bar/pkg/x.go:12 x",
                "at github.com/foo/bar/pkg/x.go:12 x",
            ),
            (
                "mount /var/lib/kubelet/pods/abc/volumes/kubernetes.io~projected/token x",
                "mount <PATH> x",
            ),
        ] {
            let (r, _) = PathDetector::detect_and_replace(input);
            assert_eq!(
                r, expected,
                "a MIME type, a version, a ns/name pair and a DNS-qualified name are not paths: {input}"
            );
        }
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn option_names_and_signed_words_are_not_paths() {
        let (r, _) = PathDetector::detect_and_replace("x # -sdown master mymaster y");
        assert_eq!(r, "x # -sdown master mymaster y");
        let (r, tokens) =
            PathDetector::detect_and_replace("run --namespace kube-system -n foo -namespace bar");
        assert_eq!(r, "run --namespace kube-system -n foo -namespace bar");
        assert!(tokens.is_empty());
    }

    #[test]
    fn a_cli_option_name_keeps_its_spelling() {
        for line in ["cp --force -t src dst", "rm -rf --no-preserve-root x"] {
            let (r, tokens) = PathDetector::detect_and_replace(line);
            assert_eq!(r, line, "an option name is a key, not a variable path");
            assert!(tokens.is_empty(), "{line}: {tokens:?}");
        }
    }

    #[test]
    fn an_escaped_flat_struct_stays_literal() {
        let (running, t1) =
            PathDetector::detect_and_replace(r#"state \"{phase:Running}\" rejected"#);
        let (failed, t2) = PathDetector::detect_and_replace(r#"state \"{phase:Failed}\" rejected"#);
        assert_eq!(
            running, r#"state \"{phase:Running}\" rejected"#,
            "its values are the event"
        );
        assert_ne!(running, failed, "Running and Failed stay two events");
        assert!(t1.is_empty() && t2.is_empty(), "{t1:?} {t2:?}");
    }

    #[test]
    fn a_syslog_program_tag_written_as_a_path_stays_whole() {
        let (r, t) = PathDetector::detect_and_replace(
            "fedora /usr/libexec/xdg-desktop-portal[997790]: Could not fstatat ns/pid: Not a directory",
        );
        assert_eq!(
            r,
            "fedora /usr/libexec/xdg-desktop-portal[997790]: Could not fstatat ns/pid: Not a directory"
        );
        assert!(
            !t.iter()
                .any(|t| matches!(t, Token::Path(p) if p.contains("libexec")))
        );
        let (r, _) = PathDetector::detect_and_replace("x /usr/libexec/xdg-desktop-portal y");
        assert_eq!(r, "x <PATH> y");
    }
}

#[cfg(test)]
mod syslog_tag_and_glue_edges {
    use super::*;

    fn m<'a>(text: &'a str, needle: &str) -> regex::Match<'a> {
        Regex::new(&regex::escape(needle))
            .unwrap()
            .find(text)
            .unwrap()
    }

    #[test]
    fn a_match_is_in_the_tag_only_when_the_spans_overlap() {
        let text = "abc  tag/x  yz/w";
        let start = text.find("tag/x").unwrap();
        let tag = Some(SyslogProgramTag {
            start,
            end: start + "tag/x".len(),
        });
        assert!(PathDetector::in_syslog_tag(tag, &m(text, "tag/x")));
        assert!(PathDetector::in_syslog_tag(tag, &m(text, "g/x")));
        assert!(!PathDetector::in_syslog_tag(tag, &m(text, "abc")));
        assert!(!PathDetector::in_syslog_tag(tag, &m(text, "yz/w")));
        assert!(
            !PathDetector::in_syslog_tag(tag, &m(text, "abc  ")),
            "touching the start is not overlap"
        );
        assert!(
            !PathDetector::in_syslog_tag(tag, &m(text, "  yz")),
            "touching the end is not overlap"
        );
        assert!(!PathDetector::in_syslog_tag(None, &m(text, "tag/x")));
    }

    #[test]
    fn glue_needs_a_word_character_before_the_match_and_never_looks_before_the_start() {
        assert!(PathDetector::is_glued_to_word(
            "x/usr/bin",
            &m("x/usr/bin", "/usr/bin")
        ));
        assert!(!PathDetector::is_glued_to_word(
            " /usr/bin",
            &m(" /usr/bin", "/usr/bin")
        ));
        assert!(!PathDetector::is_glued_to_word(
            "/usr/bin",
            &m("/usr/bin", "/usr/bin")
        ));
    }
}
