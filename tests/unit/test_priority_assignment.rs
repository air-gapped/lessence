// Unit Test: Priority Assignment (T041)
// Tests the priority assignment logic in isolation

use lessence::patterns::timestamp::{FormatFamily, PatternPriority, TimestampFormat};

#[test]
fn test_format_family_assignment() {
    // Test format family categorization
    assert_eq!(
        TimestampFormat::ISO8601Enhanced.format_family(),
        FormatFamily::Structured
    );
    assert_eq!(
        TimestampFormat::RFC3339.format_family(),
        FormatFamily::Structured
    );
    assert_eq!(
        TimestampFormat::KubernetesLog.format_family(),
        FormatFamily::Application
    );
    assert_eq!(
        TimestampFormat::DockerLog.format_family(),
        FormatFamily::Application
    );
    assert_eq!(
        TimestampFormat::USDate.format_family(),
        FormatFamily::Regional
    );
    assert_eq!(
        TimestampFormat::EuropeanDate.format_family(),
        FormatFamily::Regional
    );
    assert_eq!(
        TimestampFormat::MySQLTimestamp.format_family(),
        FormatFamily::Database
    );
    assert_eq!(
        TimestampFormat::PostgreSQLTimestamp.format_family(),
        FormatFamily::Database
    );
    assert_eq!(
        TimestampFormat::SyslogBSD.format_family(),
        FormatFamily::Legacy
    );
    assert_eq!(
        TimestampFormat::IBMFormat.format_family(),
        FormatFamily::Legacy
    );
    assert_eq!(
        TimestampFormat::UnixTimestamp.format_family(),
        FormatFamily::Unix
    );
    assert_eq!(
        TimestampFormat::UnixTimestampMs.format_family(),
        FormatFamily::Unix
    );
}

#[test]
fn test_specificity_scoring() {
    // More specific formats should have higher scores
    let iso_enhanced = TimestampFormat::ISO8601Enhanced.specificity_score();
    let iso_basic = TimestampFormat::ISO8601Full.specificity_score();
    let unix = TimestampFormat::UnixTimestamp.specificity_score();

    assert!(
        iso_enhanced >= iso_basic,
        "Enhanced ISO should have higher or equal specificity"
    );
    assert!(
        iso_basic > unix,
        "ISO should be more specific than Unix timestamps"
    );
}

#[test]
fn test_unix_timestamp_penalty() {
    let unix_priority = PatternPriority::new(50, FormatFamily::Unix);
    let structured_priority = PatternPriority::new(50, FormatFamily::Structured);

    assert!(
        unix_priority.unix_timestamp_penalty,
        "Unix timestamps should have penalty"
    );
    assert!(
        !structured_priority.unix_timestamp_penalty,
        "Structured formats should not have penalty"
    );
}

#[test]
fn test_effective_score_calculation() {
    let unix_priority = PatternPriority::new(50, FormatFamily::Unix);
    let structured_priority = PatternPriority::new(50, FormatFamily::Structured);

    let unix_score = unix_priority.effective_score();
    let structured_score = structured_priority.effective_score();

    // Unix should have much higher effective score (lower priority)
    assert!(
        unix_score > structured_score,
        "Unix effective score ({unix_score}) should be higher than structured score ({structured_score})"
    );
}

#[test]
fn test_format_family_ordering() {
    // Test that format families have correct relative priorities
    let structured = PatternPriority::new(50, FormatFamily::Structured);
    let application = PatternPriority::new(50, FormatFamily::Application);
    let regional = PatternPriority::new(50, FormatFamily::Regional);
    let database = PatternPriority::new(50, FormatFamily::Database);
    let legacy = PatternPriority::new(50, FormatFamily::Legacy);
    let unix = PatternPriority::new(50, FormatFamily::Unix);

    // Lower effective score = higher priority
    assert!(structured.effective_score() < application.effective_score());
    assert!(application.effective_score() < regional.effective_score());
    assert!(regional.effective_score() < database.effective_score());
    assert!(database.effective_score() < legacy.effective_score());
    assert!(legacy.effective_score() < unix.effective_score());
}

#[test]
fn test_priority_comparison() {
    let high_priority = PatternPriority::new(100, FormatFamily::Structured);
    let low_priority = PatternPriority::new(10, FormatFamily::Unix);

    // Higher specificity should beat lower even across families
    assert!(
        high_priority.effective_score() < low_priority.effective_score(),
        "High specificity structured pattern should beat low specificity Unix pattern"
    );
}

#[test]
fn test_same_family_specificity_ordering() {
    let high_spec = PatternPriority::new(90, FormatFamily::Application);
    let low_spec = PatternPriority::new(70, FormatFamily::Application);

    assert!(
        high_spec.effective_score() < low_spec.effective_score(),
        "Higher specificity should have lower effective score (higher priority)"
    );
}

#[test]
fn test_constitutional_unix_timestamp_lowest_priority() {
    // Constitutional requirement: Unix timestamps must be lowest priority
    let unix_timestamp = PatternPriority::new(10, FormatFamily::Unix);
    let any_structured = PatternPriority::new(10, FormatFamily::Structured);
    let any_application = PatternPriority::new(10, FormatFamily::Application);
    let any_regional = PatternPriority::new(10, FormatFamily::Regional);
    let any_database = PatternPriority::new(10, FormatFamily::Database);
    let any_legacy = PatternPriority::new(10, FormatFamily::Legacy);

    // Unix should have higher effective score (lower priority) than all others
    assert!(unix_timestamp.effective_score() > any_structured.effective_score());
    assert!(unix_timestamp.effective_score() > any_application.effective_score());
    assert!(unix_timestamp.effective_score() > any_regional.effective_score());
    assert!(unix_timestamp.effective_score() > any_database.effective_score());
    assert!(unix_timestamp.effective_score() > any_legacy.effective_score());
}

#[test]
fn test_priority_consistency() {
    // Same inputs should produce same outputs
    let priority1 = PatternPriority::new(75, FormatFamily::Application);
    let priority2 = PatternPriority::new(75, FormatFamily::Application);

    assert_eq!(priority1.effective_score(), priority2.effective_score());
    assert_eq!(
        priority1.unix_timestamp_penalty,
        priority2.unix_timestamp_penalty
    );
    assert_eq!(priority1.format_family, priority2.format_family);
}

#[test]
fn test_edge_case_specificity_scores() {
    // Test edge cases for specificity scores
    let zero_spec = PatternPriority::new(0, FormatFamily::Structured);
    let max_spec = PatternPriority::new(u32::MAX, FormatFamily::Unix);

    // Should handle edge cases without panicking
    let zero_score = zero_spec.effective_score();
    let max_score = max_spec.effective_score();

    assert!(
        zero_score <= max_score,
        "Scores should be ordered even at edges"
    );
}

#[test]
fn test_format_family_enum_completeness() {
    // Ensure all format families are tested
    let families = [
        FormatFamily::Structured,
        FormatFamily::Application,
        FormatFamily::Regional,
        FormatFamily::Database,
        FormatFamily::Legacy,
        FormatFamily::Unix,
    ];

    for family in &families {
        let priority = PatternPriority::new(50, family.clone());
        let score = priority.effective_score();
        assert!(
            score != 0 || *family == FormatFamily::Structured,
            "All families should produce valid scores"
        );
    }
}
