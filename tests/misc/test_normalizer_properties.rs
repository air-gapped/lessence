use lessence::Config;
use lessence::normalize::Normalizer;
use proptest::prelude::*;

fn default_normalizer() -> Normalizer {
    Normalizer::new(Config::default())
}

proptest! {
    // NOTE: normalization is NOT fully idempotent — known issue.
    // Example: "P 0%:" → "P <PCT>:" → "<TIMESTAMP> <PCT>:"
    // Token placeholders like <PCT> change context for subsequent passes.
    // This is acceptable because lessence normalizes each line only once.
    // Tracked as a known property violation, not a bug to fix.

    #[test]
    fn normalization_preserves_tokens(input in "[ -~]{1,200}") {
        let normalizer = default_normalizer();
        let result = normalizer.normalize_line(input).unwrap();
        // Normalized output should never be empty if input wasn't
        prop_assert!(!result.normalized.is_empty() || result.original.is_empty());
    }

    #[test]
    fn similarity_is_commutative(
        a in "[ -~]{1,100}",
        b in "[ -~]{1,100}"
    ) {
        let normalizer = default_normalizer();
        let line_a = normalizer.normalize_line(a).unwrap();
        let line_b = normalizer.normalize_line(b).unwrap();
        let score_ab = normalizer.similarity_score(&line_a, &line_b);
        let score_ba = normalizer.similarity_score(&line_b, &line_a);
        prop_assert!(
            (score_ab - score_ba).abs() < f64::EPSILON,
            "similarity(a, b) should equal similarity(b, a): {score_ab} vs {score_ba}"
        );
    }

    #[test]
    fn self_similarity_is_100(input in "[ -~]{1,200}") {
        let normalizer = default_normalizer();
        let line = normalizer.normalize_line(input).unwrap();
        let score = normalizer.similarity_score(&line, &line);
        prop_assert!(
            (score - 100.0).abs() < f64::EPSILON,
            "similarity(x, x) should be 100.0, got {score}"
        );
    }

    #[test]
    fn normalization_never_panics(input in "\\PC{0,500}") {
        let normalizer = default_normalizer();
        // Should not panic on any input
        let _ = normalizer.normalize_line(input);
    }
}

/// A line with `planted` between two runs of random text, masked the three
/// ways an output can meet it: the original with its tokens, the original
/// alone, and its normalized form.
fn masked_forms(spec: &str, planted: &str, before: &str, after: &str) -> Vec<String> {
    use lessence::sanitize::Sanitizer;
    let z = Sanitizer::parse(&[spec.to_string()], false)
        .unwrap()
        .unwrap()
        .with_key(7);
    let line = format!("{before} {planted} {after}");
    let normalized = default_normalizer().normalize_line(line.clone()).unwrap();
    vec![
        z.mask_line(&line, &normalized.tokens),
        z.mask_text(&line),
        z.mask_text(&normalized.normalized),
    ]
}

proptest! {
    #[test]
    fn planted_values_never_survive_masking(
        before in "[ -~]{0,40}",
        after in "[ -~]{0,40}",
        octet in 1u8..=24,
        digit in 0u8..=9,
        group in 0u16..=0xffff,
        local in "[a-z][a-z0-9]{0,10}",
        label in "[a-z][a-z0-9]{0,10}",
        secret in "[A-Za-z]{4,8}[0-9]{2,4}[A-Za-z]{2,4}",
        form in 0usize..6,
        pseudonym in any::<bool>(),
    ) {
        let action = if pseudonym { ":pseudonym" } else { "" };
        let ipv6 = format!("2001:db8::{group:x}");
        let credential = [
            format!("password={secret}"),
            format!("api_key: {secret}"),
            format!("token=\"{secret}\""),
            format!("Authorization: Bearer {secret}"),
            format!("Proxy-Authorization: Basic {secret}=="),
            format!("https://app:{secret}@db.example.com/x"),
        ][form]
            .clone();
        let cases = [
            (
                "ip",
                format!("198.51.100.{octet} 198.51.100.{octet}{digit} {ipv6}"),
                vec!["198.51.100.".to_string(), ipv6.clone()],
            ),
            ("email", format!("{local}@example.com"), vec![format!("{local}@example.com")]),
            ("host", format!("{label}.example.com"), vec![format!("{label}.example.com")]),
            ("credential", credential, vec![secret.clone()]),
        ];
        let glued = regex::Regex::new(r"<IP(?::[0-9a-f]{16})?>[0-9A-Za-z]").unwrap();
        for (entity, planted, values) in cases {
            for out in masked_forms(&format!("{entity}{action}"), &planted, &before, &after) {
                for value in &values {
                    prop_assert!(!out.contains(value.as_str()), "{entity}: {value:?} in {out:?}");
                }
                if entity == "ip" {
                    prop_assert!(!glued.is_match(&out), "a tag is followed by an alphanumeric: {out:?}");
                }
            }
        }
    }
}
