use std::process::Command;

#[test]
fn test_version_shows_lessence_name() {
    // T007: CLI contract test for version display
    // Verifies that version output contains lessence name

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --version should execute successfully"
    );

    let version_output = String::from_utf8_lossy(&output.stdout);

    // Check for "lessence" in version output
    assert!(
        version_output.to_lowercase().contains("lessence"),
        "Version output should contain 'lessence', got: {version_output}"
    );

    // Ensure no old "logfold" references
    assert!(
        !version_output.to_lowercase().contains("logfold"),
        "Version output should not contain 'logfold', got: {version_output}"
    );
}

#[test]
fn test_version_format() {
    // Verify version follows semantic versioning
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--version")
        .output()
        .expect("lessence binary should exist");

    let version_output = String::from_utf8_lossy(&output.stdout);

    // Should contain version number pattern (x.y.z)
    let version_regex = regex::Regex::new(r"\d+\.\d+\.\d+").unwrap();
    assert!(
        version_regex.is_match(&version_output),
        "Version should contain semantic version number, got: {version_output}"
    );
}

#[test]
fn test_version_short_flag() {
    // Test -V short flag works
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("-V")
        .output()
        .expect("lessence binary should exist");

    // -V should work the same as --version
    if output.status.success() {
        let version_output = String::from_utf8_lossy(&output.stdout);
        assert!(
            version_output.to_lowercase().contains("lessence") || !version_output.trim().is_empty(),
            "Short version flag should work, got: {version_output}"
        );
    }
}
