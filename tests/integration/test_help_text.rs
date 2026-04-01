use std::process::Command;

#[test]
fn test_help_text_contains_lessence_branding() {
    // T006: CLI contract test for help text branding
    // Verifies that help text contains proper lessence branding

    let output = Command::new("./target/release/lessence")
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --help should execute successfully"
    );

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Check for "lessence" branding in help text
    assert!(
        help_text.to_lowercase().contains("lessence"),
        "Help text should contain 'lessence' branding, got: {help_text}"
    );

    // Ensure no old "lessence" references remain
    assert!(
        !help_text.to_lowercase().contains("logfold"),
        "Help text should not contain old 'logfold' references, got: {help_text}"
    );
}

#[test]
fn test_help_text_contains_seo_description() {
    // Verify SEO-optimized description appears in help
    let output = Command::new("./target/release/lessence")
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Should contain key SEO terms
    let seo_terms = ["log compression", "essence", "intelligent", "LLM"];
    let found_terms: Vec<_> = seo_terms
        .iter()
        .filter(|term| help_text.to_lowercase().contains(&term.to_lowercase()))
        .collect();

    assert!(
        !found_terms.is_empty(),
        "Help text should contain SEO terms like 'log compression', 'essence', 'intelligent', or 'LLM', got: {help_text}"
    );
}

#[test]
fn test_help_text_structure() {
    // Verify help text has proper structure
    let output = Command::new("./target/release/lessence")
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Should contain standard help sections
    assert!(
        help_text.contains("Usage:") || help_text.contains("USAGE:"),
        "Help should contain usage section"
    );
    assert!(
        help_text.contains("Options:")
            || help_text.contains("FLAGS:")
            || help_text.contains("ARGS:"),
        "Help should contain options section"
    );
}
