use std::process::{Command, Stdio};
use std::io::Write;

#[test]
fn contract_single_thread_via_threads_flag() {
    // Test from cli_interface_api.md Test 1
    // Verify single-threaded execution works via --threads 1
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Write minimal test input
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line 1\ntest line 2\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Single-threaded execution via --threads 1 should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn contract_removed_flag_error() {
    // Test from cli_interface_api.md Test 2
    // Verify --single-thread flag is rejected with helpful error
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--single-thread"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Write minimal test input
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        !output.status.success(),
        "Should fail with removed --single-thread flag"
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "Should return Clap error code 2"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--single-thread"),
        "Error should mention removed flag. Stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("--threads") || stderr.contains("threads 1"),
        "Error should suggest replacement. Stderr: {}",
        stderr
    );
}

#[test]
fn contract_invalid_thread_count() {
    // Test from cli_interface_api.md Test 3
    // Verify thread count 0 is rejected
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--threads", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Write minimal test input
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        !output.status.success(),
        "Should fail with thread count 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Thread count must be at least 1") || stderr.contains("at least 1"),
        "Error should mention minimum thread count. Stderr: {}",
        stderr
    );
}

#[test]
fn contract_multi_thread_unchanged() {
    // Test from cli_interface_api.md Test 4
    // Verify multi-threaded execution still works
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--", "--threads", "4"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Write test input
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line 1\ntest line 2\ntest line 3\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Multi-threaded execution should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn contract_auto_detect_unchanged() {
    // Test from cli_interface_api.md Test 5
    // Verify auto-detect mode still works when no thread flag specified
    let mut child = Command::new("cargo")
        .args(&["run", "--release"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    // Write test input
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line 1\ntest line 2\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Auto-detect mode should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}