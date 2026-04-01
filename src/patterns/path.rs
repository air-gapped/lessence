use std::sync::LazyLock;
use regex::Regex;

use super::Token;


    // File system paths (Unix-style) - simplified without character class issues
static FILE_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(/[a-zA-Z0-9_.\-/]+(?:\.[a-zA-Z0-9]+)?(?:/[a-zA-Z0-9_.\-]*)*/?)")
        .expect("Failed to compile file path regex"));

    // URL paths (without domain)
static URL_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"((?:/[a-zA-Z0-9_.\-~%]*)+(?:\?[a-zA-Z0-9_.\-~%&=]*)?(?:#[a-zA-Z0-9_.\-~%]*)?)")
        .expect("Failed to compile URL path regex"));

    // Full URLs with schemes (https://host/path) - capture the entire URL
static FULL_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^/\s]+(?:/[^\s"]*)"#)
        .expect("Failed to compile full URL regex"));

    // Windows paths
static WINDOWS_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([A-Za-z]:\\[a-zA-Z0-9_.\-\\]+(?:\\[a-zA-Z0-9_.\-]*)*\\?)")
        .expect("Failed to compile Windows path regex"));

    // Query parameters (standalone)
static QUERY_PARAMS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\?([a-zA-Z0-9_\-]+=([^&\s]+)(&[a-zA-Z0-9_\-]+=([^&\s]+))*)")
        .expect("Failed to compile query params regex"));

    // Route parameters in paths (like /users/123/posts/456, /namespaces/kube-system/pods/pod-name)
static ROUTE_PARAMS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/([0-9a-fA-F]{8,}|[0-9]{3,}|[a-fA-F0-9\-]{8,})")
        .expect("Failed to compile route params regex"));

    // Variable text segments in paths (like /namespaces/NAME/serviceaccounts/NAME)
static PATH_SEGMENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/([a-zA-Z0-9][a-zA-Z0-9\-]{2,}[a-zA-Z0-9])")
        .expect("Failed to compile path segments regex"));

    // Source file with line number pattern (like file.go:1234])
static SOURCE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-zA-Z_][a-zA-Z0-9_\-]*\.(go|rs|py|js|java|c|cpp|h|hpp|rb|php|ts|tsx|jsx|cs|swift|kt|m|mm|scala|clj|ex|exs|erl|hrl)):\d+\]")
        .expect("Failed to compile source line regex"));

    // CLI flags pattern (like --flag-name or -f)
static CLI_FLAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s--?[a-zA-Z][a-zA-Z0-9\-_]*")
        .expect("Failed to compile CLI flag regex"));

    // JSON-like structures and embedded objects
    // Matches {key:value...} or escaped JSON \"{}\"
static JSON_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(\\"?\{[\\"\w\s:,\[\]$/_-]*\}\\"?)"#)
        .expect("Failed to compile JSON structure regex"));

    // Event objects that span multiple lines
static EVENT_OBJECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&Event\{[^}]*\}")
        .expect("Failed to compile event object regex"));

pub struct PathDetector;

impl PathDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace Event objects first (they're more specific)
        result = EVENT_OBJECT.replace_all(&result, |caps: &regex::Captures| {
            let event = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(event.to_string()));
            "<EVENT_OBJECT>".to_string()
        }).to_string();

        // Replace JSON structures (like {volumeName:..., podName:...})
        result = JSON_STRUCT.replace_all(&result, |caps: &regex::Captures| {
            let json = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(json.to_string()));

            // Try to identify what type of structure it is
            if json.contains("volumeName:") {
                "<VOLUME_SPEC>"
            } else if json.contains("ObjectMeta:") {
                "<K8S_OBJECT>"
            } else {
                "<JSON_DATA>"
            }.to_string()
        }).to_string();

        // Replace CLI flags (like --flag-name)
        result = CLI_FLAG.replace_all(&result, |caps: &regex::Captures| {
            let flag = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(flag.trim().to_string()));
            " <FLAG>".to_string()
        }).to_string();

        // Replace source file:line patterns (before other path detection)
        // This normalizes file.go:1234] to file.go:<LINE>]
        result = SOURCE_LINE.replace_all(&result, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let filename = caps.get(1).unwrap().as_str();
            tokens.push(Token::Path(matched.to_string()));
            format!("{}:<LINE>]", filename)
        }).to_string();

        // Replace full URLs NEXT (https://host/path) - must run before file paths
        // Otherwise the /path part gets detected as a file path
        result = FULL_URL.replace_all(&result, |caps: &regex::Captures| {
            let full_url = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(full_url.to_string()));
            "<PATH>".to_string()
        }).to_string();

        // Replace file system paths (Unix-style)
        result = FILE_PATH.replace_all(&result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            if Self::is_likely_file_path(path) {
                tokens.push(Token::Path(path.to_string()));
                "<PATH>".to_string()
            } else {
                caps[0].to_string()
            }
        }).to_string();

        // Replace Windows paths
        result = WINDOWS_PATH.replace_all(&result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            tokens.push(Token::Path(path.to_string()));
            "<PATH>".to_string()
        }).to_string();

        // Replace URL paths and query parameters
        result = URL_PATH.replace_all(&result, |caps: &regex::Captures| {
            let path = caps.get(1).unwrap().as_str();
            if Self::is_likely_url_path(path) {
                let normalized = Self::normalize_url_path(path);
                tokens.push(Token::Path(path.to_string()));
                normalized
            } else {
                caps[0].to_string()
            }
        }).to_string();

        (result, tokens)
    }

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
        let has_extension = path.contains('.') &&
            path.split('/').next_back().unwrap_or("").contains('.');
        let has_multiple_segments = path.matches('/').count() > 1;
        let has_common_dirs = path.contains("/var/") ||
            path.contains("/usr/") ||
            path.contains("/etc/") ||
            path.contains("/home/") ||
            path.contains("/opt/") ||
            path.contains("/tmp/");

        has_extension || has_multiple_segments || has_common_dirs
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
        let has_api_patterns = path.contains("/api/") ||
            path.contains("/v1/") ||
            path.contains("/v2/") ||
            path.starts_with("/static/") ||
            path.starts_with("/assets/");
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
        normalized = PATH_SEGMENTS.replace_all(&normalized, |caps: &regex::Captures| {
            let segment = caps.get(1).unwrap().as_str();

            // Keep common fixed API segments unchanged
            match segment {
                "api" | "v1" | "v2" | "v3" | "alpha" | "beta" |
                "namespaces" | "pods" | "services" | "deployments" |
                "configmaps" | "secrets" | "serviceaccounts" |
                "token" | "status" | "proxy" | "logs" | "exec" |
                "static" | "assets" | "public" | "health" | "metrics" => {
                    format!("/{}", segment)
                }
                _ => "/<PATH>".to_string()
            }
        }).to_string();

        // Replace query parameter values
        normalized = QUERY_PARAMS.replace_all(&normalized, |caps: &regex::Captures| {
            let full_query = caps.get(1).unwrap().as_str();
            let parts: Vec<&str> = full_query.split('&').collect();
            let normalized_parts: Vec<String> = parts.iter().map(|part| {
                if let Some(eq_pos) = part.find('=') {
                    format!("{}=<PATH>", &part[..eq_pos])
                } else {
                    part.to_string()
                }
            }).collect();
            format!("?{}", normalized_parts.join("&"))
        }).to_string();

        normalized
    }

    #[allow(dead_code)]
    pub fn detect_and_replace_flags(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace CLI flags with <FLAG>
        result = CLI_FLAG.replace_all(&result, |caps: &regex::Captures| {
            let flag = caps.get(0).unwrap().as_str();
            tokens.push(Token::Path(flag.trim().to_string()));
            " <FLAG>".to_string()
        }).to_string();

        (result, tokens)
    }

    #[allow(dead_code)]
    pub fn is_valid_path(path: &str) -> bool {
        // Basic validation - not empty and reasonable length
        !path.is_empty() && path.len() < 1000
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
            assert_eq!(PathDetector::is_likely_file_path(path), expected, "Failed for path: {}", path);
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
            assert_eq!(PathDetector::is_likely_url_path(path), expected, "Failed for path: {}", path);
        }
    }

    #[test]
    fn test_path_normalization() {
        let test_cases = vec![
            ("Error in /var/log/app.2025-01-20.log", "Error in <PATH>"),
            ("GET /api/users/123/posts", "GET <PATH>"),
            // "search" is not in the fixed API segments list, so it becomes <PATH> too
            ("Request to /search?q=test&page=5", "Request to /<PATH>?q=<PATH>&page=<PATH>"),
            (r"C:\Users\john\Documents\file.txt", "<PATH>"),
        ];

        for (input, expected) in test_cases {
            let (result, _tokens) = PathDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }
}
