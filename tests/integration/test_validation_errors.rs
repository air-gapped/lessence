use std::io::Write;
use std::process::Stdio;
use std::time::Instant;

#[test]
fn test_validation_fails_fast_no_stdin_read() {
    let start = Instant::now();

    let mut child = crate::common::lessence()
        .args(["--threads", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        let large_line = "A".repeat(10000);
        for _ in 0..100 {
            let _ = stdin.write_all(large_line.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for command");
    let duration = start.elapsed();

    assert!(!output.status.success(), "Should exit with error");

    assert!(
        duration.as_secs() < 5,
        "validation runs before stdin is read, so it fails fast however large the input (took {duration:?}, expected <5s)"
    );
}

#[test]
fn test_pattern_error_lists_all_valid_patterns() {
    let output = crate::common::lessence()
        .args(["--disable-patterns", "invalid"])
        .output()
        .expect("Failed to run command");

    assert!(!output.status.success(), "Should exit with error");

    let stderr = String::from_utf8_lossy(&output.stderr);

    let expected_patterns = vec![
        "timestamp",
        "hash",
        "network",
        "uuid",
        "email",
        "path",
        "duration",
        "json",
        "kubernetes",
        "http-status",
        "brackets",
        "key-value",
        "process",
        "quoted-string",
        "name",
    ];

    for pattern in expected_patterns {
        assert!(
            stderr.contains(pattern),
            "Error should list pattern '{pattern}'. Got: {stderr}"
        );
    }
}

#[test]
fn test_validation_accepts_large_valid_values() {
    let mut child = crate::common::lessence()
        .args(["--threads", "999999"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test\n").ok();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Should accept large valid thread count. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
