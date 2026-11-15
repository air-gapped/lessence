use std::fs;

#[test]
fn test_readme_contains_lessence_branding() {
    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");

    assert!(
        readme_content.contains("# lessence") || readme_content.contains("# Lessence"),
        "README should have 'lessence' in main title"
    );

    assert!(
        readme_content.to_lowercase().contains("lessence"),
        "README should contain 'lessence' references"
    );

    let logfold_lines: Vec<_> = readme_content
        .lines()
        .filter(|line| line.to_lowercase().contains("logfold"))
        .filter(|line| {
            !line.to_lowercase().contains("renamed")
                && !line.to_lowercase().contains("previously")
                && !line.to_lowercase().contains("formerly")
                && !line.to_lowercase().contains("started as")
        })
        .collect();

    assert!(
        logfold_lines.is_empty(),
        "README should not contain non-historical 'logfold' references: {logfold_lines:?}"
    );
}

#[test]
fn test_readme_installation_examples_use_lessence() {
    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");

    let installation_section = readme_content.to_lowercase();

    if installation_section.contains("install") || installation_section.contains("usage") {
        assert!(
            readme_content.contains("lessence"),
            "Installation/usage examples should use 'lessence'"
        );
    }
}

#[test]
fn test_claude_md_updated_with_lessence() {
    let claude_content = fs::read_to_string("CLAUDE.md").expect("CLAUDE.md should exist");

    assert!(
        claude_content.to_lowercase().contains("lessence"),
        "CLAUDE.md should contain 'lessence' references"
    );

    assert!(
        claude_content.contains("# CLAUDE.md - lessence"),
        "CLAUDE.md should have updated project title"
    );
}

#[test]
fn test_documentation_consistency() {
    let readme_content = fs::read_to_string("README.md").expect("README.md should exist");
    let claude_content = fs::read_to_string("CLAUDE.md").expect("CLAUDE.md should exist");

    assert!(
        readme_content.to_lowercase().contains("lessence"),
        "README.md should contain lessence branding"
    );
    assert!(
        claude_content.to_lowercase().contains("lessence"),
        "CLAUDE.md should contain lessence branding"
    );

    let claude_logfold_count = claude_content.matches("logfold").count();
    assert_eq!(
        claude_logfold_count, 0,
        "CLAUDE.md should have zero logfold references, found: {claude_logfold_count}"
    );
}
