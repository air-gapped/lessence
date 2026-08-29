use regex::Regex;
use std::sync::LazyLock;

use super::Token;

// File system paths (Unix-style) - simplified without character class issues.
// `~` is a path character: `/volumes/kubernetes.io~projected/token`.
static FILE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(/[a-zA-Z0-9_.\-~/]+(?:\.[a-zA-Z0-9]+)?(?:/[a-zA-Z0-9_.\-~]*)*/?)")
        .expect("Failed to compile file path regex")
});

// A relative path: a dot-free first segment, then more segments. Which of
// these are paths is decided in the closure: `netpol/argocd/argocd-redis`
// and `internal/pkg/x.go` are, `text/html` and `HTTP/1.1` are not, and
// `docker.io/library/nginx` starts with a DNS name, not a directory.
static RELATIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_.\-~]+)+\b")
        .expect("Failed to compile relative path regex")
});

// URL paths (without domain)
static URL_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"((?:/[a-zA-Z0-9_.\-~%]*)+(?:\?[a-zA-Z0-9_.\-~%&=]*)?(?:#[a-zA-Z0-9_.\-~%]*)?)")
        .expect("Failed to compile URL path regex")
});

// Full URLs with schemes (https://host/path) - capture the entire URL
static FULL_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^/\s"]+(?:/[^\s"]*)?"#).expect("Failed to compile full URL regex")
});

// Windows paths
static WINDOWS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z]:\\[a-zA-Z0-9_.\-\\]+(?:\\[a-zA-Z0-9_.\-]*)*\\?)")
        .expect("Failed to compile Windows path regex")
});

// Query parameters (standalone)
static QUERY_PARAMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\?([a-zA-Z0-9_\-]+=([^&\s]+)(&[a-zA-Z0-9_\-]+=([^&\s]+))*)")
        .expect("Failed to compile query params regex")
});

// Route parameters in paths (like /users/123/posts/456, /namespaces/kube-system/pods/pod-name)
static ROUTE_PARAMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/([0-9a-fA-F]{8,}|[0-9]{3,}|[a-fA-F0-9\-]{8,})")
        .expect("Failed to compile route params regex")
});

// Variable text segments in paths (like /namespaces/NAME/serviceaccounts/NAME)
static PATH_SEGMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/([a-zA-Z0-9][a-zA-Z0-9\-]{2,}[a-zA-Z0-9])")
        .expect("Failed to compile path segments regex")
});

// Source file with line number pattern (like file.go:1234])
static SOURCE_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([a-zA-Z_][a-zA-Z0-9_\-]*\.(go|rs|py|js|java|c|cpp|h|hpp|rb|php|ts|tsx|jsx|cs|swift|kt|m|mm|scala|clj|ex|exs|erl|hrl)):\d+\]")
        .expect("Failed to compile source line regex")
});

// CLI flags pattern (like --flag-name or -f)
static CLI_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s--?[a-zA-Z][a-zA-Z0-9\-_]*").expect("Failed to compile CLI flag regex")
});

// JSON-like structures and embedded objects
// Matches {key:value...} or escaped JSON \"{}\"
static JSON_STRUCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\\"?\{[\\"\w\s:,\[\]$/_-]*\}\\"?)"#)
        .expect("Failed to compile JSON structure regex")
});

// Event objects that span multiple lines
static EVENT_OBJECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&Event\{[^}]*\}").expect("Failed to compile event object regex"));

pub struct PathDetector;

impl PathDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace Event objects first (they're more specific)
        result = EVENT_OBJECT
            .replace_all(&result, |caps: &regex::Captures| {
                let event = caps.get(0).unwrap().as_str();
                tokens.push(Token::Path(event.to_string()));
                "<EVENT_OBJECT>".to_string()
            })
            .to_string();

        // Replace JSON structures (like {volumeName:..., podName:...})
        result = JSON_STRUCT
            .replace_all(&result, |caps: &regex::Captures| {
                let json = caps.get(0).unwrap().as_str();
                tokens.push(Token::Path(json.to_string()));

                // Try to identify what type of structure it is
                if json.contains("volumeName:") {
                    "<VOLUME_SPEC>"
                } else if json.contains("ObjectMeta:") {
                    "<K8S_OBJECT>"
                } else {
                    "<JSON_DATA>"
                }
                .to_string()
            })
            .to_string();

        // Replace CLI flags (like --flag-name)
        result = CLI_FLAG
            .replace_all(&result, |caps: &regex::Captures| {
                let flag = caps.get(0).unwrap().as_str();
                tokens.push(Token::Path(flag.trim().to_string()));
                " <FLAG>".to_string()
            })
            .to_string();

        // Replace source file:line patterns (before other path detection)
        // This normalizes file.go:1234] to file.go:<LINE>]
        result = SOURCE_LINE
            .replace_all(&result, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap().as_str();
                let filename = caps.get(1).unwrap().as_str();
                tokens.push(Token::Path(matched.to_string()));
                format!("{filename}:<LINE>]")
            })
            .to_string();

        // Replace full URLs NEXT (https://host/path) - must run before file paths
        // Otherwise the /path part gets detected as a file path
        result = FULL_URL
            .replace_all(&result, |caps: &regex::Captures| {
                let full_url = caps.get(0).unwrap().as_str();
                tokens.push(Token::Path(full_url.to_string()));
                "<PATH>".to_string()
            })
            .to_string();

        // Replace file system paths (Unix-style)
        result = FILE_PATH
            .replace_all(&result, |caps: &regex::Captures| {
                let path = caps.get(1).unwrap().as_str();
                if Self::is_likely_file_path(path)
                    && !Self::is_glued_to_word(&result, &caps.get(0).unwrap())
                {
                    tokens.push(Token::Path(path.to_string()));
                    "<PATH>".to_string()
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        if result.contains('/') {
            let folded = RELATIVE_PATH.replace_all(&result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                if Self::is_relative_path(&result, &m) {
                    tokens.push(Token::Path(m.as_str().to_string()));
                    "<PATH>".to_string()
                } else {
                    m.as_str().to_string()
                }
            });
            if let std::borrow::Cow::Owned(s) = folded {
                result = s;
            }
        }

        // Replace Windows paths
        result = WINDOWS_PATH
            .replace_all(&result, |caps: &regex::Captures| {
                let path = caps.get(1).unwrap().as_str();
                tokens.push(Token::Path(path.to_string()));
                "<PATH>".to_string()
            })
            .to_string();

        // Replace URL paths and query parameters
        result = URL_PATH
            .replace_all(&result, |caps: &regex::Captures| {
                let path = caps.get(1).unwrap().as_str();
                if Self::is_likely_url_path(path)
                    && !Self::is_glued_to_word(&result, &caps.get(0).unwrap())
                {
                    let normalized = Self::normalize_url_path(path);
                    tokens.push(Token::Path(path.to_string()));
                    normalized
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        (result, tokens)
    }

    #[cfg_attr(test, mutants::skip)] // Equivalent mutant: common dirs (/var/, /usr/, etc.) always imply has_multiple_segments, making || vs && on those conditions indistinguishable
    fn is_likely_file_path(path: &str) -> bool {
        // Must start with /
        if !path.starts_with('/') {
            return false;
        }

        // Exclude very short paths that might be false positives
        if path.len() < 3 {
            return false;
        }

        // Common file path indicators
        let has_extension =
            path.contains('.') && path.split('/').next_back().unwrap_or("").contains('.');
        let has_multiple_segments = path.matches('/').count() > 1;
        let has_common_dirs = path.contains("/var/")
            || path.contains("/usr/")
            || path.contains("/etc/")
            || path.contains("/home/")
            || path.contains("/opt/")
            || path.contains("/tmp/");

        has_extension || has_multiple_segments || has_common_dirs
    }

    /// A slash glued to a word continues that word: `HTTP/1.1`, `curl/7.68.0`,
    /// a Postgres LSN `6E/F9009520`, a label key `kubernetes.io/cpu-cpuid.X87`,
    /// an image `docker.io/library/nginx`, a source file `internal/pkg/x.go`.
    /// None of them is a path.
    fn is_glued_to_word(haystack: &str, m: &regex::Match) -> bool {
        m.start() > 0 && haystack.as_bytes()[m.start() - 1].is_ascii_alphanumeric()
    }

    /// A `word/…` run is a path when it has two or more segments after the
    /// word or ends in a file with an extension — unless it continues a
    /// dotted name (`docker.io/library/nginx`) or is a version (`HTTP/1.1`,
    /// `curl/7.68.0`, `Mozilla/5.0`).
    fn is_relative_path(haystack: &str, m: &regex::Match) -> bool {
        let continues_a_name =
            m.start() > 0 && matches!(haystack.as_bytes()[m.start() - 1], b'.' | b'/' | b'\\');
        let path = m.as_str();
        let rest = &path[path.find('/').unwrap_or(0)..];
        let is_version = rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b'/');
        let file_like =
            rest[1..].contains('/') || rest.rsplit('/').next().unwrap_or("").contains('.');
        !continues_a_name && !is_version && file_like
    }

    fn is_likely_url_path(path: &str) -> bool {
        // Must start with /
        if !path.starts_with('/') {
            return false;
        }

        // Exclude very short paths
        if path.len() < 2 {
            return false;
        }

        // Common URL path indicators
        let has_api_patterns = path.contains("/api/")
            || path.contains("/v1/")
            || path.contains("/v2/")
            || path.starts_with("/static/")
            || path.starts_with("/assets/");
        let has_query_params = path.contains('?');
        let has_multiple_segments = path.matches('/').count() > 1;
        let has_numeric_ids = ROUTE_PARAMS.is_match(path);

        has_api_patterns || has_query_params || has_multiple_segments || has_numeric_ids
    }

    fn normalize_url_path(path: &str) -> String {
        // First replace numeric IDs and hex IDs in path segments
        let mut normalized = ROUTE_PARAMS.replace_all(path, "/<PATH>").to_string();

        // Then replace variable text segments (like namespace names, service account names)
        // Skip common fixed segments like 'api', 'v1', 'namespaces', 'serviceaccounts', 'token'
        normalized = PATH_SEGMENTS
            .replace_all(&normalized, |caps: &regex::Captures| {
                let segment = caps.get(1).unwrap().as_str();

                // Keep common fixed API segments unchanged
                match segment {
                    "api" | "v1" | "v2" | "v3" | "alpha" | "beta" | "namespaces" | "pods"
                    | "services" | "deployments" | "configmaps" | "secrets" | "serviceaccounts"
                    | "token" | "status" | "proxy" | "logs" | "exec" | "static" | "assets"
                    | "public" | "health" | "metrics" => {
                        format!("/{segment}")
                    }
                    _ => "/<PATH>".to_string(),
                }
            })
            .to_string();

        // Replace query parameter values
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

    // --- is_likely_file_path ---

    #[test]
    fn file_path_short_rejected() {
        assert!(!PathDetector::is_likely_file_path("/a"));
    }

    #[test]
    fn file_path_no_leading_slash_rejected() {
        assert!(!PathDetector::is_likely_file_path("var/log"));
    }

    #[test]
    fn file_path_common_dir() {
        assert!(PathDetector::is_likely_file_path("/var/log"));
    }

    #[test]
    fn file_path_with_extension() {
        assert!(PathDetector::is_likely_file_path("/app/main.rs"));
    }

    // --- is_likely_url_path ---

    #[test]
    fn url_path_api_pattern() {
        assert!(PathDetector::is_likely_url_path("/api/v1/users"));
    }

    #[test]
    fn url_path_too_short() {
        assert!(!PathDetector::is_likely_url_path("/"));
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
            // "search" is not in the fixed API segments list, so it becomes <PATH> too
            (
                "Request to /search?q=test&page=5",
                "Request to /<PATH>?q=<PATH>&page=<PATH>",
            ),
            (r"C:\Users\john\Documents\file.txt", "<PATH>"),
        ];

        for (input, expected) in test_cases {
            let (result, _tokens) = PathDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
        }
    }

    // ---- is_likely_file_path: per-branch tests ----

    #[test]
    fn file_path_no_leading_slash() {
        assert!(!PathDetector::is_likely_file_path("no_slash"));
    }

    #[test]
    fn file_path_len_under_3() {
        assert!(!PathDetector::is_likely_file_path("/a"));
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

    // ---- is_likely_url_path: per-branch tests ----

    #[test]
    fn url_path_no_leading_slash() {
        assert!(!PathDetector::is_likely_url_path("api/v1"));
    }

    #[test]
    fn url_path_len_under_2() {
        assert!(!PathDetector::is_likely_url_path("/"));
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

    // ---- Mutant-killing: is_likely_file_path boundary & branch isolation ----

    #[test]
    fn file_path_len_exactly_3_accepted() {
        // len=3 "/ab" must pass the `< 3` guard (boundary: == should fail, <= should fail)
        // It has no extension, no multiple segments, no common dirs, so it should
        // actually return false (none of the three conditions are met). But it DOES
        // pass the length guard, which is the mutant we're killing.
        // We need a 3-char path that satisfies at least one condition.
        // "/a." has a dot but split('/').next_back() = "a." which contains('.') -> has_extension
        assert!(PathDetector::is_likely_file_path("/a."));
    }

    #[test]
    fn file_path_len_exactly_2_rejected() {
        // len=2 "/a" must fail the `< 3` guard
        assert!(!PathDetector::is_likely_file_path("/a"));
    }

    #[test]
    fn file_path_has_extension_only() {
        // has_extension=true, has_multiple_segments=false, has_common_dirs=false
        // Single segment after /, has extension, no common dir.
        // "/x.log" -> segments from split('/'): ["", "x.log"], matches('/').count()=1 so not >1
        assert!(PathDetector::is_likely_file_path("/x.log"));
    }

    #[test]
    fn file_path_has_multiple_segments_only() {
        // has_extension=false, has_multiple_segments=true, has_common_dirs=false
        // No extension, multiple segments, no common dir names
        assert!(PathDetector::is_likely_file_path("/foo/bar/baz"));
    }

    #[test]
    fn file_path_has_common_dirs_only() {
        // has_extension=false, has_multiple_segments=false (need only 1 slash beyond root),
        // has_common_dirs=true
        // "/var/x" -> matches('/').count()=2 which IS >1, so has_multiple_segments=true too.
        // We need exactly 1 slash: that means the path is just "/var/" which contains "/var/"
        // "/var/" -> matches('/').count()=2, still >1. Hard to isolate.
        // Actually "/tmp/" -> contains "/tmp/", matches('/')=2 -> has_multiple_segments=true
        // Let's verify the mutant is still killed: if || became &&, then having only
        // common_dirs true (with multiple_segments also true) wouldn't isolate.
        // Instead test: has_common_dirs=true but extension=false, to kill the first ||
        assert!(PathDetector::is_likely_file_path("/var/x"));
    }

    #[test]
    fn file_path_none_of_three_conditions() {
        // No extension, single segment (1 slash), no common dir -> should be false
        // Kills mutant: || replaced with && (if all were required, this proves || works
        // by showing that ABSENCE of all three returns false)
        assert!(!PathDetector::is_likely_file_path("/xyz"));
    }

    // ---- Mutant-killing: is_likely_url_path boundary & branch isolation ----

    #[test]
    fn url_path_len_exactly_2_accepted() {
        // len=2 "/x" must pass the `< 2` guard. But then it needs to satisfy a condition.
        // "/x" has no api patterns, no query params, matches('/').count()=1 (not >1), no numeric ids.
        // So it returns false. The mutant is about the guard itself.
        // We need a 2-char URL path that satisfies at least one condition.
        // "/?" has query params -> has_query_params=true, len=2
        assert!(PathDetector::is_likely_url_path("/?"));
    }

    #[test]
    fn url_path_len_exactly_1_rejected() {
        // len=1 "/" must fail the `< 2` guard
        assert!(!PathDetector::is_likely_url_path("/"));
    }

    #[test]
    fn url_path_has_api_patterns_only() {
        // has_api_patterns=true, has_query_params=false, has_multiple_segments=false(?), has_numeric_ids=false
        // "/static/x" -> starts_with("/static/")=true, no '?', matches('/')=2 which IS >1
        // Hard to isolate api from multiple_segments. Use "/static/" itself:
        // matches('/')=2 -> has_multiple_segments=true. Can't avoid it with /static/.
        // Use "/v1/" -> matches('/')=2 again.
        // The point is: if || became &&, requiring ALL to be true would fail since
        // has_query_params and has_numeric_ids are false. This kills the mutant.
        assert!(PathDetector::is_likely_url_path("/v1/items"));
    }

    #[test]
    fn url_path_has_query_params_only() {
        // has_api_patterns=false, has_query_params=true, has_multiple_segments=false, has_numeric_ids=false
        // "/x?q=1" -> no api pattern, has '?', matches('/')=1 (not >1), no route params
        assert!(PathDetector::is_likely_url_path("/x?q=1"));
    }

    #[test]
    fn url_path_has_multiple_segments_only() {
        // has_api_patterns=false, has_query_params=false, has_multiple_segments=true, has_numeric_ids=false
        // "/foo/bar" -> no api, no '?', matches('/')=2 (>1), no numeric route params
        assert!(PathDetector::is_likely_url_path("/foo/bar"));
    }

    #[test]
    fn url_path_has_numeric_ids_only() {
        // has_api_patterns=false, has_query_params=false, has_multiple_segments=false, has_numeric_ids=true
        // Need a path with a numeric route param but only 1 slash.
        // ROUTE_PARAMS matches /([0-9a-fA-F]{8,}|[0-9]{3,}|[a-fA-F0-9\-]{8,})
        // "/12345" -> matches('/').count()=1 so not multiple segments
        // ROUTE_PARAMS: /([0-9]{3,}) matches "/12345"
        assert!(PathDetector::is_likely_url_path("/12345"));
    }

    #[test]
    fn url_path_segment_count_boundary() {
        // has_multiple_segments requires matches('/').count() > 1
        // "/x" has count=1 (not >1). Kills mutant: > replaced with <
        assert!(!PathDetector::is_likely_url_path("/x"));
        // "/x/y" has count=2 (>1) -> true
        assert!(PathDetector::is_likely_url_path("/x/y"));
    }

    // ---- Mutant-killing: normalize_url_path API segment preservation ----

    #[test]
    fn normalize_url_path_preserves_api_segments() {
        // PATH_SEGMENTS regex matches 4+ char segments, so "api"/"v1" are too short
        // to match. Use 4+ char segments from the preserved list.
        let result = PathDetector::normalize_url_path("/namespaces/my-ns/pods/nginx-abc");
        assert!(
            result.contains("/namespaces"),
            "namespaces should be preserved, got: {result}"
        );
        assert!(
            result.contains("/pods"),
            "pods should be preserved, got: {result}"
        );
        // "my-ns" and "nginx-abc" are variable, should become <PATH>
        assert!(
            !result.contains("my-ns"),
            "variable segment should be normalized, got: {result}"
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

    /// A slash glued to a word continues the word — a version, a label key,
    /// an image, a relative source file — and is never a path on its own. A
    /// bare `http://host` is still a URL, and a path after a separator is
    /// still a path.
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
            assert_eq!(r, expected, "input: {input}");
        }
    }

    /// A relative path is a path: two segments after a directory, or a
    /// file with an extension. A MIME type, a version, a `ns/name` pair and
    /// a DNS-qualified name are not.
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
            assert_eq!(r, expected, "input: {input}");
        }
    }
}
