use regex::Regex;
use std::sync::LazyLock;

use super::Token;

// JSON-like structures and embedded objects
// Matches {key:value...} or escaped JSON \"{}\"
static JSON_STRUCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\\"?\{[\\"\w\s:,\[\]$/_-]*\}\\"?)"#)
        .expect("Failed to compile JSON structure regex")
});

// Event objects that span multiple lines
static EVENT_OBJECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&Event\{[^}]*\}").expect("Failed to compile event object regex"));

pub struct JsonDetector;

impl JsonDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Replace Event objects first (they're more specific)
        result = EVENT_OBJECT
            .replace_all(&result, |caps: &regex::Captures| {
                let event = caps.get(0).unwrap().as_str();
                tokens.push(Token::Json(event.to_string()));
                "<EVENT_OBJECT>".to_string()
            })
            .to_string();

        // Replace JSON structures (like {volumeName:..., podName:...})
        result = JSON_STRUCT
            .replace_all(&result, |caps: &regex::Captures| {
                let json = caps.get(0).unwrap().as_str();
                tokens.push(Token::Json(json.to_string()));

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

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_struct_volume_spec() {
        // JSON_STRUCT matches escaped JSON structures
        let input = r#"spec \"{volumeName: test-vol, podName: test-pod}\""#;
        let (result, tokens) = JsonDetector::detect_and_replace(input);
        assert!(
            result.contains("<VOLUME_SPEC>"),
            "should detect volume spec: {result}"
        );
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_json_struct_k8s_object() {
        let input = r#"object \"{ObjectMeta: name_test}\""#;
        let (result, tokens) = JsonDetector::detect_and_replace(input);
        assert!(
            result.contains("<K8S_OBJECT>"),
            "should detect K8s object: {result}"
        );
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_json_struct_generic() {
        let input = r#"data \"{key: value, status: ok}\""#;
        let (result, tokens) = JsonDetector::detect_and_replace(input);
        assert!(
            result.contains("<JSON_DATA>"),
            "should detect generic JSON: {result}"
        );
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_json_structure_detection() {
        // EVENT_OBJECT regex matches &Event{...}
        let matching_cases = vec![("&Event{Type: Warning}", "<EVENT_OBJECT>")];

        for (input, expected_replacement) in matching_cases {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert!(
                result.contains(expected_replacement),
                "Failed for input: {input} - expected: {expected_replacement} - got: {result}"
            );
            assert!(!tokens.is_empty(), "No tokens found for input: {input}");
        }

        // Plain JSON-like structures without backslash prefix are not detected
        let non_matching_cases = vec![
            "{volumeName: test-vol, podName: test-pod}",
            "{ObjectMeta: {name: test}}",
            "{generic: data}",
        ];

        for input in non_matching_cases {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert_eq!(result, input, "Should not match for input: {input}");
            assert!(
                tokens.is_empty(),
                "Should have no tokens for input: {input}"
            );
        }
    }
}
