use std::fs;

#[test]
fn test_readme_contains_lessence_branding() {
    // T009: Documentation consistency test
    // Verifies that README contains proper lessence branding

    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");

    // Check for lessence branding in title/header
    assert!(
        readme_content.contains("# lessence") || readme_content.contains("# Lessence"),
        "README should have 'lessence' in main title"
    );

    // Should contain lessence references
    assert!(
        readme_content.to_lowercase().contains("lessence"),
        "README should contain 'lessence' references"
    );

    // Should not contain old logfold references (except historical context)
    let logfold_lines: Vec<_> = readme_content
        .lines()
        .filter(|line| line.to_lowercase().contains("logfold"))
        .filter(|line| {
            !line.to_lowercase().contains("renamed")
                && !line.to_lowercase().contains("previously")
                && !line.to_lowercase().contains("formerly")
        })
        .collect();

    assert!(
        logfold_lines.is_empty(),
        "README should not contain non-historical 'logfold' references: {logfold_lines:?}"
    );
}

#[test]
fn test_readme_installation_examples_use_lessence() {
    // Verify installation examples use correct binary name
    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");

    // Find installation/usage sections
    let installation_section = readme_content.to_lowercase();

    if installation_section.contains("install") || installation_section.contains("usage") {
        // Should show lessence in examples
        assert!(
            readme_content.contains("lessence"),
            "Installation/usage examples should use 'lessence'"
        );
    }
}

#[test]
fn test_claude_md_updated_with_lessence() {
    // Verify CLAUDE.md project documentation is updated
    let claude_content = fs::read_to_string("CLAUDE.md").expect("CLAUDE.md should exist");

    // Check for lessence references in project documentation
    assert!(
        claude_content.to_lowercase().contains("lessence"),
        "CLAUDE.md should contain 'lessence' references"
    );

    // Title should be updated
    assert!(
        claude_content.contains("# CLAUDE.md - lessence"),
        "CLAUDE.md should have updated project title"
    );
}

#[test]
fn test_documentation_consistency() {
    // Verify consistent branding across all docs
    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");
    let claude_content = fs::read_to_string("CLAUDE.md").expect("CLAUDE.md should exist");

    // Both should use consistent "lessence" branding
    assert!(
        readme_content.to_lowercase().contains("lessence"),
        "README.md should contain lessence branding"
    );
    assert!(
        claude_content.to_lowercase().contains("lessence"),
        "CLAUDE.md should contain lessence branding"
    );

    // Neither should have stray logfold references
    let readme_logfold_count = readme_content.matches("logfold").count();
    let claude_logfold_count = claude_content.matches("logfold").count();

    // After transition completion, should have zero logfold references
    assert_eq!(
        readme_logfold_count, 0,
        "README.md should have zero logfold references, found: {readme_logfold_count}"
    );
    assert_eq!(
        claude_logfold_count, 0,
        "CLAUDE.md should have zero logfold references, found: {claude_logfold_count}"
    );
}
