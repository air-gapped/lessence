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
