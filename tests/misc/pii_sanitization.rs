use regex::Regex;
use std::io::Write;
use std::process::Command;

#[test]
fn test_no_email_leakage_in_output() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--sanitize-pii")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"admin@company.com failed auth\n").unwrap();
        stdin.write_all(b"user@external.org logged in\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Email detection regex (RFC 5322 simplified)
    let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z|a-z]{2,}").unwrap();

    // Critical: NO email addresses should be found
    let matches: Vec<_> = email_regex.find_iter(&stdout).collect();
    assert_eq!(
        matches.len(),
        0,
        "Found {} email(s) in sanitized output: {:?}",
        matches.len(),
        matches
    );
}

#[test]
fn test_gdpr_compliance_basic_deidentification() {
    // GDPR Article 4(5): Pseudonymization = direct identifiers removed
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--sanitize-pii")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        // Customer email = direct identifier under GDPR
        stdin
            .write_all(b"Customer john.doe@company.eu submitted complaint\n")
            .unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Verify no direct email identifier remains
    assert!(!stdout.contains("john.doe@company.eu"));
    assert!(!stdout.contains('@'));
    assert!(stdout.contains("<EMAIL>"), "Should use pseudonymized token");
}

#[test]
fn test_hipaa_compliance_safe_harbor_method() {
    // HIPAA Safe Harbor: Remove 18 identifiers (email is one)
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--sanitize-pii")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        // Patient email = HIPAA identifier
        stdin
            .write_all(b"Patient contact: patient123@hospital.org\n")
            .unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Verify email identifier removed per Safe Harbor
    assert!(!stdout.contains("patient123@hospital.org"));
    assert!(stdout.contains("<EMAIL>"));
}
