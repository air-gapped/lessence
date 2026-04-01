use std::process::{Command, Stdio};
use std::io::Write;
use std::time::Instant;

#[test]
fn test_validation_fails_fast_no_stdin_read() {
    // Validation should happen before stdin reading
    // Even with large input, error should be instant
    
    let start = Instant::now();
    
    let mut child = Command::new("cargo")
        .args(["run", "--release", "--", "--threads", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Try to write large input (should not be consumed)
    if let Some(mut stdin) = child.stdin.take() {
        let large_line = "A".repeat(10000);
        for _ in 0..100 {
            let _ = stdin.write_all(large_line.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child.wait_with_output().expect("Failed to wait for command");
    let duration = start.elapsed();

    assert!(
        !output.status.success(),
        "Should exit with error"
    );

    // Validation should be instant (<1 second even with large input)
    assert!(
        duration.as_secs() < 5,
        "Validation should fail fast (took {:?}, expected <5s)",
        duration
    );
}

#[test]
fn test_pattern_error_lists_all_valid_patterns() {
    let output = Command::new("cargo")
        .args(["run", "--release", "--", "--disable-patterns", "invalid"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Verify all 15 pattern names are listed
    let expected_patterns = vec![
        "timestamp", "hash", "network", "uuid", "email", "path", "duration",
        "json", "kubernetes", "http-status", "brackets", "key-value",
        "process", "quoted-string", "name", "decimal"
    ];
    
    for pattern in expected_patterns {
        assert!(
            stderr.contains(pattern),
            "Error should list pattern '{}'. Got: {}",
            pattern,
            stderr
        );
    }
}

#[test]
fn test_validation_accepts_large_valid_values() {
    let mut child = Command::new("cargo")
        .args(["run", "--release", "--", "--threads", "999999"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    // Should accept very large valid values (system will limit threads naturally)
    assert!(
        output.status.success(),
        "Should accept large valid thread count. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
