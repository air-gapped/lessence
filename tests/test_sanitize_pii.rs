use std::io::Write;
use std::process::Command;

#[test]
fn test_sanitize_pii_text_format() {
    let mut child = Command::new("./target/release/lessence")
        .arg("--sanitize-pii")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(b"User alice@example.com logged in\n")
            .unwrap();
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("<EMAIL>"), "Should contain <EMAIL> token");
    assert!(
        !stdout.contains("alice@example.com"),
        "Should NOT contain plain email"
    );
}

// JSON format was removed; test_sanitize_pii_json_format deleted as no longer applicable.

#[test]
fn test_sanitize_pii_markdown_format() {
    let mut child = Command::new("./target/release/lessence")
        .args(["--sanitize-pii", "--format", "markdown"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin
            .write_all(b"support@example.com ticket created\n")
            .unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("<EMAIL>"), "Markdown should have <EMAIL>");
    assert!(
        !stdout.contains("support@example.com"),
        "Markdown should NOT have plain email"
    );
}

#[test]
fn test_sanitize_pii_cross_format_consistency() {
    let input = b"Email: alice@example.com logged in\n";

    // Test text format
    let text_output = run_lessence(&["--sanitize-pii"], input);

    // Test markdown format (JSON format was removed)
    let md_output = run_lessence(&["--sanitize-pii", "--format", "markdown"], input);

    // Both formats should mask the email
    assert!(text_output.contains("<EMAIL>"));
    assert!(md_output.contains("<EMAIL>"));

    // Neither should contain plain email
    assert!(!text_output.contains("alice@example.com"));
    assert!(!md_output.contains("alice@example.com"));
}

// Helper function
fn run_lessence(args: &[&str], input: &[u8]) -> String {
    let mut cmd = Command::new("./target/release/lessence");
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn test_sanitize_pii_with_email_disabled() {
    // Conflicting flags: sanitize emails but email detection disabled
    let mut child = Command::new("./target/release/lessence")
        .args(["--sanitize-pii", "--disable-patterns", "email"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"user@example.com logged in\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Email detection disabled → no tokens → no masking
    // This is expected behavior (document in quickstart troubleshooting)
    assert!(
        stdout.contains("user@example.com"),
        "Email not detected, so not masked"
    );
}
