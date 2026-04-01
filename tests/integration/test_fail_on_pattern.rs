use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

#[test]
fn test_exits_1_when_pattern_matches() {
    let mut child = lessence_bin()
        .args(["--fail-on-pattern", "ERROR", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "ERROR something failed").ok();
        writeln!(stdin, "INFO all good").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert_eq!(output.status.code(), Some(1), "Should exit 1 when pattern matches");
}

#[test]
fn test_exits_0_when_pattern_does_not_match() {
    let mut child = lessence_bin()
        .args(["--fail-on-pattern", "ERROR", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "INFO all good").ok();
        writeln!(stdin, "DEBUG trace info").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert_eq!(output.status.code(), Some(0), "Should exit 0 when no match");
}

#[test]
fn test_exits_2_on_invalid_regex() {
    let mut child = lessence_bin()
        .args(["--fail-on-pattern", "[invalid", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "test").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert_eq!(output.status.code(), Some(2), "Should exit 2 on invalid regex");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid regex"), "Should print error message: {}", stderr);
}

#[test]
fn test_output_still_produced_when_pattern_matches() {
    let mut child = lessence_bin()
        .args(["--fail-on-pattern", "ERROR", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "ERROR something failed").ok();
        writeln!(stdin, "INFO all good").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Output should still be produced when pattern matches");
    assert!(stdout.contains("ERROR"), "Output should contain the matched line");
    assert_eq!(output.status.code(), Some(1), "But exit code should be 1");
}
