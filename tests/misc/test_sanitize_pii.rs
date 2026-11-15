use std::io::Write;

#[test]
fn test_sanitize_pii_text_format() {
    let mut child = crate::common::lessence()
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

#[test]
fn test_sanitize_pii_markdown_format() {
    let mut child = crate::common::lessence()
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

    let text_output = run_lessence(&["--sanitize-pii"], input);

    let md_output = run_lessence(&["--sanitize-pii", "--format", "markdown"], input);

    assert!(
        text_output.contains("<EMAIL>"),
        "text format masks the email"
    );
    assert!(
        md_output.contains("<EMAIL>"),
        "markdown format masks the email"
    );

    assert!(
        !text_output.contains("alice@example.com"),
        "text format holds no plain email"
    );
    assert!(
        !md_output.contains("alice@example.com"),
        "markdown format holds no plain email"
    );
}

fn run_lessence(args: &[&str], input: &[u8]) -> String {
    let mut cmd = crate::common::lessence();
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
    let mut child = crate::common::lessence()
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

    assert!(
        stdout.contains("<EMAIL> logged in"),
        "masking does not depend on the email detector: {stdout}"
    );
    assert!(
        !stdout.contains("user@example.com"),
        "masking does not depend on the email detector: {stdout}"
    );
}

#[test]
fn test_sanitize_pii_masks_credential_assignment() {
    let stdout = run_lessence(&["--sanitize-pii"], b"login password=hunter2fixture ok\n");
    assert!(
        stdout.contains("<SECRET>"),
        "Should mask a credential value (lessence-q9y): {stdout}"
    );
    assert!(
        !stdout.contains("hunter2fixture"),
        "Fixture secret must not survive: {stdout}"
    );
}

#[test]
fn test_sanitize_pii_masks_jwt() {
    let stdout = run_lessence(
        &["--sanitize-pii"],
        b"auth Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmN\n",
    );
    assert!(
        stdout.contains("<JWT>"),
        "Should mask JWT (lessence-q9y): {stdout}"
    );
    assert!(
        !stdout.contains("eyJhbGciOiJIUzI1NiJ9"),
        "Fixture JWT must not survive: {stdout}"
    );
}

#[test]
fn test_sanitize_pii_masks_provider_key() {
    let stdout = run_lessence(&["--sanitize-pii"], b"push with ghp_FixtureAbCd1234EfGh\n");
    assert!(
        stdout.contains("<KEY>"),
        "Should mask provider key (lessence-q9y): {stdout}"
    );
    assert!(
        !stdout.contains("ghp_FixtureAbCd1234EfGh"),
        "Fixture key must not survive: {stdout}"
    );
}

#[test]
fn test_credentials_pass_through_without_flag() {
    let stdout = run_lessence(&[], b"login password=hunter2fixture ok\n");
    assert!(
        stdout.contains("password=hunter2fixture"),
        "Masking is opt-in: without the flag the line must pass through: {stdout}"
    );
}

#[test]
fn test_sanitize_pii_json_no_secret_in_any_field() {
    let input = b"auth req token=FIXTURESECRET1 done\n\
                  auth req token=FIXTURESECRET2 done\n\
                  auth req token=FIXTURESECRET3 done\n\
                  auth req token=FIXTURESECRET4 done\n";
    let stdout = run_lessence(&["--sanitize-pii", "--format", "json"], input);
    assert!(
        !stdout.contains("FIXTURESECRET"),
        "No fixture secret may appear in any JSON field (first.line, last.line, \
         variation samples): {stdout}"
    );
    assert!(stdout.contains("<SECRET>"), "Should mask values: {stdout}");
}
