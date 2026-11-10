use regex::Regex;
use std::sync::LazyLock;

use super::Token;

// A Kubernetes Event's metadata block only; see the copy in path.rs.
static EVENT_OBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&Event\{ObjectMeta:\{[^}]*\}").expect("Failed to compile event object regex")
});

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

        // An escaped flat struct stays literal; see the copy in path.rs.

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An escaped flat struct is the event's own words: `{phase:Running}`
    /// and `{phase:Failed}` must not read as one `<JSON_DATA>`.
    #[test]
    fn an_escaped_flat_struct_stays_literal() {
        for input in [
            r#"spec \"{volumeName: test-vol, podName: test-pod}\""#,
            r#"object \"{ObjectMeta: name_test}\""#,
            r#"state \"{phase:Running}\" rejected"#,
            r#"state \"{phase:Failed}\" rejected"#,
        ] {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert_eq!(result, input);
            assert!(tokens.is_empty(), "{input}: {tokens:?}");
        }
    }

    #[test]
    fn test_json_structure_detection() {
        // EVENT_OBJECT matches an Event's metadata block; the reason and
        // everything else after it stay.
        let (result, tokens) = JsonDetector::detect_and_replace(
            "&Event{ObjectMeta:{web-a.17f3  default    0 map[] []},Reason:Pulled}",
        );
        assert_eq!(result, "<EVENT_OBJECT>,Reason:Pulled}");
        assert_eq!(tokens.len(), 1);

        // An Event without that block is not folded whole.
        let (flat, _) = JsonDetector::detect_and_replace("&Event{Type: Warning}");
        assert!(!flat.contains("<EVENT_OBJECT>"), "{flat}");

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
