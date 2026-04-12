use regex::Regex;
use std::sync::LazyLock;

use super::Token;

// Generic hyphenated names with variable suffixes
// Matches patterns like: component-name-suffix, kube-api-access-suffix
static HYPHENATED_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*)-([a-z0-9]{5,})\b")
        .expect("Failed to compile hyphenated names regex")
});

// Common prefixes that should be preserved (not treated as variable)
static COMMON_PREFIXES: &[&str] = &[
    "kube-api-access",
    "kube-proxy",
    "kube-controller",
    "kube-scheduler",
    "nvidia-device-plugin",
    "nvidia-container-toolkit",
    "node-feature-discovery",
    "container-runtime",
    "csi-rbdplugin",
    "virt-handler",
    "cilium-envoy",
];

pub struct NameDetector;

impl NameDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no hyphens (most lines won't have hyphenated names)
        if !text.contains('-') {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace hyphenated names with variable suffixes
        result = HYPHENATED_NAMES
            .replace_all(&result, |caps: &regex::Captures| {
                let prefix = caps.get(1).unwrap().as_str();
                let suffix = caps.get(2).unwrap().as_str();
                let full_name = caps.get(0).unwrap().as_str();

                // Check if this looks like a variable suffix (hash-like or random)
                if Self::is_variable_suffix(suffix) {
                    // Check if the prefix is a known common pattern
                    if Self::is_common_prefix(prefix) {
                        tokens.push(Token::Name(full_name.to_string()));
                        format!("{prefix}-<SUFFIX>")
                    } else {
                        // Generic component name
                        tokens.push(Token::Name(full_name.to_string()));
                        "<COMPONENT>-<SUFFIX>".to_string()
                    }
                } else {
                    // Keep original if suffix doesn't look variable
                    full_name.to_string()
                }
            })
            .to_string();

        (result, tokens)
    }

    fn is_variable_suffix(suffix: &str) -> bool {
        // Variable suffixes are typically:
        // - 5+ characters mixed alphanumeric (hash-like)
        // - Contains both letters and numbers
        // - Exclude common English words

        if suffix.len() < 5 {
            return false;
        }

        // Exclude common English words that aren't variable
        let common_words = &[
            "stable", "latest", "master", "worker", "server", "client", "proxy", "cache", "store",
            "admin", "config", "service",
        ];
        if common_words.contains(&suffix) {
            return false;
        }

        let has_letters = suffix.chars().any(char::is_alphabetic);
        let has_numbers = suffix.chars().any(char::is_numeric);
        let all_lowercase = suffix.chars().all(|c| c.is_lowercase() || c.is_numeric());

        // Only accept if it has both letters and numbers (hash-like)
        has_letters && has_numbers && all_lowercase
    }

    fn is_common_prefix(prefix: &str) -> bool {
        COMMON_PREFIXES.contains(&prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyphenated_name_detection() {
        let test_cases = vec![
            (
                "pod pushprox-kube-proxy-client-9djm4",
                "pod <COMPONENT>-<SUFFIX>",
            ),
            (
                "volume kube-api-access-52r58",
                "volume kube-api-access-<SUFFIX>",
            ),
            ("container cilium-kh8lj", "container <COMPONENT>-<SUFFIX>"),
            ("service nginx-stable", "service nginx-stable"), // Short suffix, unchanged
            ("app my-service", "app my-service"),             // Too short, unchanged
        ];

        for (input, expected) in test_cases {
            let (result, _tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
        }
    }

    #[test]
    fn test_variable_suffix_detection() {
        assert!(NameDetector::is_variable_suffix("9djm4")); // mixed alphanumeric
        assert!(NameDetector::is_variable_suffix("52r58")); // mixed alphanumeric
        assert!(NameDetector::is_variable_suffix("kh8lj")); // mixed alphanumeric
        // "abcde" is all letters with no numbers — the code requires both letters AND numbers
        assert!(!NameDetector::is_variable_suffix("abcde"));

        assert!(!NameDetector::is_variable_suffix("abc")); // too short
        assert!(!NameDetector::is_variable_suffix("stable")); // common word
        assert!(!NameDetector::is_variable_suffix("123")); // too short
    }

    #[test]
    fn variable_suffix_boundary_4_chars() {
        assert!(!NameDetector::is_variable_suffix("ab1c")); // exactly 4 — too short
    }

    #[test]
    fn variable_suffix_boundary_5_chars() {
        assert!(NameDetector::is_variable_suffix("ab1c2")); // exactly 5 — accepted
    }
}
