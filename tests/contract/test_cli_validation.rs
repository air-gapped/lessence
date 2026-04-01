use std::process::{Command, Stdio};
use std::io::Write;

#[test]
fn test_min_collapse_rejects_zero() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--min-collapse", "0"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for --min-collapse 0");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be at least 2"),
        "Error message should explain minimum value. Got: {}",
        stderr
    );
}

#[test]
fn test_min_collapse_rejects_one() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--min-collapse", "1"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for --min-collapse 1");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be at least 2"),
        "Error message should explain minimum value. Got: {}",
        stderr
    );
}

#[test]
fn test_threads_rejects_zero() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--threads", "0"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for --threads 0");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be at least 1"),
        "Error message should explain minimum value. Got: {}",
        stderr
    );
    assert!(
        stderr.contains("single-threaded mode"),
        "Error should mention --threads 1 option. Got: {}",
        stderr
    );
}

#[test]
fn test_max_lines_rejects_zero() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--max-lines", "0"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for --max-lines 0");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be at least 1"),
        "Error message should explain minimum value. Got: {}",
        stderr
    );
}

#[test]
fn test_max_lines_rejects_negative() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--max-lines", "-100"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for --max-lines -100");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Clap will reject negative numbers during parsing
    assert!(
        !output.status.success(),
        "Should fail parsing negative number"
    );
}

#[test]
fn test_disable_patterns_rejects_invalid_name() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--disable-patterns", "invalidpattern"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for invalid pattern");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown pattern 'invalidpattern'"),
        "Error should identify invalid pattern. Got: {}",
        stderr
    );
    assert!(
        stderr.contains("Valid patterns:"),
        "Error should list valid patterns. Got: {}",
        stderr
    );
}

#[test]
fn test_disable_patterns_rejects_mixed_valid_invalid() {
    let output = Command::new("cargo")
        .args(&["run", "--release", "--", "--disable-patterns", "timestamp,badpattern,email"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error for mixed valid/invalid patterns");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown pattern 'badpattern'"),
        "Error should identify which pattern is invalid. Got: {}",
        stderr
    );
}

#[test]
fn test_disable_patterns_accepts_valid_names() {
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--disable-patterns", "timestamp,email"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept valid pattern names. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_min_collapse_accepts_two() {
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--min-collapse", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"a\na\na\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept min-collapse 2 (boundary value). Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_threads_accepts_one() {
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept threads 1 (single-threaded mode). Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_max_lines_accepts_one() {
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--max-lines", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"line1\nline2\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept max-lines 1 (boundary value). Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_pattern_validation_case_insensitive() {
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--disable-patterns", "TIMESTAMP,Email"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept case-insensitive pattern names. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
