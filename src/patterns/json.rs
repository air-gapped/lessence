use super::Token;

pub struct JsonDetector;

impl JsonDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut tokens = Vec::new();

        let result = super::EVENT_OBJECT_META
            .replace_all(text, |caps: &regex::Captures| {
                let event = caps.get(0).unwrap().as_str();
                tokens.push(Token::EmbeddedJson(event.to_string()));
                "<EVENT_OBJECT>"
            })
            .into_owned();

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn event_object_folds_only_the_metadata_block() {
        let (result, tokens) = JsonDetector::detect_and_replace(
            "&Event{ObjectMeta:{web-a.17f3  default    0 map[] []},Reason:Pulled}",
        );
        assert_eq!(
            result, "<EVENT_OBJECT>,Reason:Pulled}",
            "the reason and everything after the metadata block stay"
        );
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn an_event_object_with_a_nested_annotation_folds_its_whole_metadata_block() {
        let (result, _) = JsonDetector::detect_and_replace(
            r#"&Event{ObjectMeta:{web-a default map[example.test/config:{"ready":true}]},Reason:Pulled}"#,
        );
        assert_eq!(result, "<EVENT_OBJECT>,Reason:Pulled}");
    }

    #[test]
    fn an_event_without_an_object_meta_block_is_not_folded_whole() {
        let (flat, _) = JsonDetector::detect_and_replace("&Event{Type: Warning}");
        assert!(!flat.contains("<EVENT_OBJECT>"), "{flat}");
    }

    #[test]
    fn a_brace_struct_without_the_event_prefix_is_not_detected() {
        for input in [
            "{volumeName: test-vol, podName: test-pod}",
            "{ObjectMeta: {name: test}}",
            "{generic: data}",
        ] {
            let (result, tokens) = JsonDetector::detect_and_replace(input);
            assert_eq!(result, input, "Should not match for input: {input}");
            assert!(
                tokens.is_empty(),
                "Should have no tokens for input: {input}"
            );
        }
    }
}
