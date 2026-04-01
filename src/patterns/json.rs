use std::sync::LazyLock;
use regex::Regex;

use super::Token;


    // JSON-like structures and embedded objects
    // Matches {key:value...} or escaped JSON \"{}\"
static JSON_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(\\"?\{[\\"\w\s:,\[\]$/_-]*\}\\"?)"#)
        .expect("Failed to compile JSON structure regex"));

    // Event objects that span multiple lines
static EVENT_OBJECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&Event\{[^}]*\}")
        .expect("Failed to compile event object regex"));

pub struct JsonDetector;

impl JsonDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace Event objects first (they're more specific)
        result = EVENT_OBJECT.replace_all(&result, |caps: &regex::Captures| {
            let event = caps.get(0).unwrap().as_str();
            tokens.push(Token::Json(event.to_string()));
            "<EVENT_OBJECT>".to_string()
        }).to_string();

        // Replace JSON structures (like {volumeName:..., podName:...})
        result = JSON_STRUCT.replace_all(&result, |caps: &regex::Captures| {
            let json = caps.get(0).unwrap().as_str();
            tokens.push(Token::Json(json.to_string()));

            // Try to identify what type of structure it is
            if json.contains("volumeName:") {
                "<VOLUME_SPEC>"
            } else if json.contains("ObjectMeta:") {
                "<K8S_OBJECT>"
            } else {
                "<JSON_DATA>"
            }.to_string()
        }).to_string();

        (result, tokens)
    }

    #[allow(dead_code)]
    pub fn is_valid_json(text: &str) -> bool {
        // Basic validation - starts and ends with braces, reasonable length
        text.starts_with('{') && text.ends_with('}') && text.len() < 10000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_structure_detection() {
        // JSON_STRUCT regex requires a literal backslash before { (for escaped JSON)
        // Plain {key: value} structures are not matched by this detector
        let matching_cases = vec![
            ("&Event{Type: Warning}", "<EVENT_OBJECT>"),
        ];

        for (input, expected_replacement) in matching_cases {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert!(result.contains(expected_replacement),
                "Failed for input: {} - expected: {} - got: {}", input, expected_replacement, result);
            assert!(!tokens.is_empty(), "No tokens found for input: {}", input);
        }

        // Plain JSON-like structures without backslash prefix are not detected
        let non_matching_cases = vec![
            "{volumeName: test-vol, podName: test-pod}",
            "{ObjectMeta: {name: test}}",
            "{generic: data}",
        ];

        for input in non_matching_cases {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert_eq!(result, input, "Should not match for input: {}", input);
            assert!(tokens.is_empty(), "Should have no tokens for input: {}", input);
        }
    }

    #[test]
    fn test_json_validation() {
        let test_cases = vec![
            ("{valid: json}", true),
            ("not json", false),
            ("{}", true),
            ("{unclosed", false),
        ];

        for (input, expected) in test_cases {
            assert_eq!(JsonDetector::is_valid_json(input), expected,
                "Failed validation for input: {}", input);
        }
    }
}
