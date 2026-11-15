#[test]
fn test_email_statistics_shown_in_report() {
    let test_input = "2025-09-26T10:15:00Z User john@company.com logged in from 192.168.1.100\n\
                      2025-09-26T10:15:01Z User admin@company.com logged in from 192.168.1.101\n\
                      2025-09-26T10:15:02Z User sarah@company.com logged in from 192.168.1.102\n";

    let output = crate::common::lessence()
        .arg("--no-report")
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

    assert!(
        stderr_str.contains("emails 3/"),
        "the briefing tokens line (lessence-xxz) lists each class as occurrences/distinct \
         (lessence-nn3) and should include 'emails 3/', got: {stderr_str}"
    );

    println!("✅ Email statistics are shown correctly in the briefing tokens line");
}

#[test]
fn test_email_statistics_hidden_when_zero() {
    let test_input = "2025-09-26T10:15:00Z Server started on port 8080\n\
                      2025-09-26T10:15:01Z Listening on 192.168.1.100:8080\n";

    let output = crate::common::lessence()
        .arg("--no-report")
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

    assert!(
        !stderr_str.contains("emails "),
        "tokens line should NOT include 'emails' when count is 0, got: {stderr_str}"
    );

    println!("✅ Email statistics are hidden correctly when count is 0");
}

#[test]
fn test_email_statistics_in_essence_mode() {
    let test_input = "2025-09-26T10:15:00Z User john@company.com logged in\n\
                      2025-09-26T10:15:01Z User admin@company.com logged in\n\
                      2025-09-26T10:15:02Z User sarah@company.com logged in\n\
                      2025-09-26T10:15:03Z User mike@company.com logged in\n";

    let output = crate::common::lessence()
        .args(["--essence", "--no-report"])
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

    assert!(
        output_str.contains("<EMAIL>"),
        "Essence mode output should contain <EMAIL> tokens"
    );

    assert!(
        stderr_str.contains("emails 4/"),
        "tokens line should include 'emails 4/' in essence mode, got: {stderr_str}"
    );

    println!("✅ Email statistics work correctly in essence mode");
}

#[test]
fn test_email_not_grouped_with_numbers() {
    let test_input = "2025-09-26T10:15:00Z CPU usage: 85% for user@domain.com\n\
                      2025-09-26T10:15:01Z CPU usage: 92% for admin@domain.com\n";

    let output = crate::common::lessence()
        .arg("--no-report")
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

    assert!(
        stderr_str.contains("emails 2/"),
        "tokens line should include 'emails 2/', got: {stderr_str}"
    );
    assert!(
        stderr_str.contains("numbers 2/"),
        "tokens line should include 'numbers 2/' as a separate class, got: {stderr_str}"
    );

    println!("✅ Email patterns are tracked separately from numbers/numbers");
}

#[test]
fn test_email_in_pattern_order_documentation() {
    use std::fs;

    let readme = fs::read_to_string("README.md").expect("Failed to read README.md");

    assert!(
        readme.contains("email"),
        "README.md should mention email in detected patterns"
    );

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
