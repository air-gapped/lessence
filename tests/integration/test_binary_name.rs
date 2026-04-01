use std::process::Command;

#[test]
fn test_lessence_binary_exists() {
    // T005: CLI contract test for binary name
    // Verifies that the lessence binary exists and executes properly

    let output = Command::new("./target/release/lessence")
        .arg("--version")
        .output();

    match output {
        Ok(result) => {
            assert!(
                result.status.success(),
                "lessence binary should execute successfully"
            );

            let version_output = String::from_utf8_lossy(&result.stdout);
            assert!(
                version_output.contains("lessence"),
                "Version output should contain 'lessence', got: {version_output}"
            );
        }
        Err(_) => {
            panic!("lessence binary should exist at ./target/release/lessence");
        }
    }
}

#[test]
fn test_lessence_binary_help() {
    // Verify lessence binary responds to help
    let output = Command::new("./target/release/lessence")
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --help should execute successfully"
    );

    let help_output = String::from_utf8_lossy(&output.stdout);
    assert!(!help_output.is_empty(), "Help output should not be empty");
}
