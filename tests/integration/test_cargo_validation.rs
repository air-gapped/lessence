use std::fs;
use toml::Value;

#[test]
fn test_cargo_toml_package_name_is_lessence() {
    // T008: File validation test for Cargo.toml changes
    // Verifies that Cargo.toml contains proper lessence configuration

    let cargo_content = fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");

    let cargo_toml: Value = cargo_content
        .parse()
        .expect("Cargo.toml should be valid TOML");

    // Check package name
    let package_name = cargo_toml
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .expect("Package name should exist");

    assert_eq!(
        package_name, "lessence",
        "Package name should be 'lessence', got: {package_name}"
    );
}

#[test]
fn test_cargo_toml_binary_name_is_lessence() {
    // Verify binary section specifies lessence
    let cargo_content = fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");

    let cargo_toml: Value = cargo_content
        .parse()
        .expect("Cargo.toml should be valid TOML");

    // Check binary name
    if let Some(bin_section) = cargo_toml.get("bin") {
        if let Some(bin_array) = bin_section.as_array() {
            let lessence_bin = bin_array
                .iter()
                .find(|bin| bin.get("name").and_then(|n| n.as_str()) == Some("lessence"));

            assert!(
                lessence_bin.is_some(),
                "Binary section should contain 'lessence' binary"
            );
        }
    }
}

#[test]
fn test_cargo_toml_description_is_seo_optimized() {
    // Verify description contains SEO keywords
    let cargo_content = fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");

    let cargo_toml: Value = cargo_content
        .parse()
        .expect("Cargo.toml should be valid TOML");

    let description = cargo_toml
        .get("package")
        .and_then(|p| p.get("description"))
        .and_then(|d| d.as_str())
        .expect("Package description should exist");

    // Should contain SEO terms
    let seo_terms = ["essence", "log", "compression", "intelligent", "LLM"];
    let found_terms: Vec<_> = seo_terms
        .iter()
        .filter(|term| description.to_lowercase().contains(&term.to_lowercase()))
        .collect();

    assert!(
        !found_terms.is_empty(),
        "Description should contain SEO terms, got: {description}"
    );

    // Should not contain old references
    assert!(
        !description.to_lowercase().contains("logfold"),
        "Description should not contain 'logfold', got: {description}"
    );
}

#[test]
fn test_cargo_toml_keywords_are_optimized() {
    // Verify keywords are SEO-optimized
    let cargo_content = fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");

    let cargo_toml: Value = cargo_content
        .parse()
        .expect("Cargo.toml should be valid TOML");

    if let Some(keywords) = cargo_toml
        .get("package")
        .and_then(|p| p.get("keywords"))
        .and_then(|k| k.as_array())
    {
        let keyword_strings: Vec<String> = keywords
            .iter()
            .filter_map(|k| k.as_str())
            .map(|s| s.to_string())
            .collect();

        // Should contain relevant keywords
        let expected_keywords = [
            "log-compression",
            "cli",
            "llm-preprocessing",
            "devops",
            "analysis",
        ];
        let found_keywords: Vec<_> = expected_keywords
            .iter()
            .filter(|keyword| keyword_strings.iter().any(|k| k.contains(*keyword)))
            .collect();

        assert!(
            !found_keywords.is_empty(),
            "Keywords should contain relevant terms, got: {keyword_strings:?}"
        );
    }
}
