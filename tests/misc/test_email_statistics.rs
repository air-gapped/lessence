// Contract Tests for Email Pattern Statistics Tracking
// Feature: 014-email-not-shown
// These tests define the expected behavior for email statistics tracking.
//
// The stderr report used to be a "Pattern Distribution" markdown table; it
// is now the orientation briefing's `tokens:` line (lessence-xxz), a
// comma-separated `class occurrences/distinct` list (lessence-nn3 added the
// `/distinct` half). These tests were updated to match.

use std::process::Command;

/// Contract 1: Email statistics must be tracked separately from other pattern types
///
/// Given: A log file containing email addresses
/// When: lessence processes the file
/// Then: The briefing's tokens line must include an "emails" entry with correct count
#[test]
fn test_email_statistics_shown_in_report() {
    // Test input with 3 email addresses
    let test_input = "2025-09-26T10:15:00Z User john@company.com logged in from 192.168.1.100\n\
                      2025-09-26T10:15:01Z User admin@company.com logged in from 192.168.1.101\n\
                      2025-09-26T10:15:02Z User sarah@company.com logged in from 192.168.1.102\n";

    // Run lessence with test input
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(test_input.as_bytes())?;
            child.wait_with_output()
        })
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let stderr_str = String::from_utf8(output.stderr).expect("Invalid UTF-8 stderr");

    // Verify the tokens line includes an emails entry with the right count
    // (3 emails in input). A trailing comma or the line's end both close it.
    assert!(
        stderr_str.contains("emails 3/"),
        "tokens line should include 'emails 3/', got: {stderr_str}"
    );

    println!("✅ Email statistics are shown correctly in the briefing tokens line");
}

/// Contract 2: Email statistics must be hidden when no emails are detected
///
/// Given: A log file containing NO email addresses
/// When: lessence processes the file
/// Then: The tokens line must NOT include an "emails" entry
#[test]
fn test_email_statistics_hidden_when_zero() {
    // Test input with NO email addresses
    let test_input = "2025-09-26T10:15:00Z Server started on port 8080\n\
                      2025-09-26T10:15:01Z Listening on 192.168.1.100:8080\n";

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(test_input.as_bytes())?;
            child.wait_with_output()
        })
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let stderr_str = String::from_utf8(output.stderr).expect("Invalid UTF-8 stderr");

    // Verify the tokens line does NOT include an emails entry when count is 0
    assert!(
        !stderr_str.contains("emails "),
        "tokens line should NOT include 'emails' when count is 0, got: {stderr_str}"
    );

    println!("✅ Email statistics are hidden correctly when count is 0");
}

/// Contract 3: Email statistics must work in essence mode
///
/// Given: A log file containing email addresses processed in essence mode
/// When: lessence --essence processes the file
/// Then: Email statistics must be displayed correctly (same as standard mode)
#[test]
fn test_email_statistics_in_essence_mode() {
    // Test input with 4 email addresses
    let test_input = "2025-09-26T10:15:00Z User john@company.com logged in\n\
                      2025-09-26T10:15:01Z User admin@company.com logged in\n\
                      2025-09-26T10:15:02Z User sarah@company.com logged in\n\
                      2025-09-26T10:15:03Z User mike@company.com logged in\n";

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--essence"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(test_input.as_bytes())?;
            child.wait_with_output()
        })
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let output_str = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    let stderr_str = String::from_utf8(output.stderr).expect("Invalid UTF-8 stderr");

    // Verify essence mode output contains <EMAIL> tokens
    assert!(
        output_str.contains("<EMAIL>"),
        "Essence mode output should contain <EMAIL> tokens"
    );

    // Verify the tokens line includes an emails entry with the right count
    // (4 emails in input).
    assert!(
        stderr_str.contains("emails 4/"),
        "tokens line should include 'emails 4/' in essence mode, got: {stderr_str}"
    );

    println!("✅ Email statistics work correctly in essence mode");
}

/// Contract 4: Email patterns must not be grouped with percentages/numbers
///
/// Given: A log file containing both email addresses and numeric patterns
/// When: lessence processes the file
/// Then: Email patterns must appear in their own category, not in "percentages"
#[test]
fn test_email_not_grouped_with_percentages() {
    // Test input with emails and numbers
    let test_input = "2025-09-26T10:15:00Z CPU usage: 85% for user@domain.com\n\
                      2025-09-26T10:15:01Z CPU usage: 92% for admin@domain.com\n";

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(test_input.as_bytes())?;
            child.wait_with_output()
        })
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let stderr_str = String::from_utf8(output.stderr).expect("Invalid UTF-8 stderr");

    // Verify both emails and percentages appear as separate token classes,
    // each with their own count (2 each — not merged into one entry).
    assert!(
        stderr_str.contains("emails 2/"),
        "tokens line should include 'emails 2/', got: {stderr_str}"
    );
    assert!(
        stderr_str.contains("percentages 2/"),
        "tokens line should include 'percentages 2/' as a separate class, got: {stderr_str}"
    );

    println!("✅ Email patterns are tracked separately from percentages/numbers");
}

/// Contract 5: Documentation consistency - README.md must include Email in pattern order
///
/// Given: README.md documentation file
/// When: Checking the "Pattern Detection Order" section
/// Then: README must list "Email" in the pattern order list
#[test]
fn test_email_in_pattern_order_documentation() {
    use std::fs;

    let readme = fs::read_to_string("README.md").expect("Failed to read README.md");

    // README should list detected patterns including email
    assert!(
        readme.contains("email"),
        "README.md should mention email in detected patterns"
    );

    // Verify ordering: timestamp before email before path
    let pattern_line = readme
        .lines()
        .find(|l| l.contains("timestamp") && l.contains("email") && l.contains("path"))
        .expect("README.md should have a line listing pattern order");

    let ts_pos = pattern_line.find("timestamp").unwrap();
    let em_pos = pattern_line.find("email").unwrap();
    let pa_pos = pattern_line.find("path").unwrap();
    assert!(
        ts_pos < em_pos && em_pos < pa_pos,
        "Pattern order should be: timestamp, email, path"
    );
}
