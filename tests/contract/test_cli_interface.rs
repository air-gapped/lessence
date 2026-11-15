use std::io::Write;
use std::process::{Command, Stdio};

// cross runs tests with HOME=/, which is unwritable, so reports go under target/.
fn lessence() -> Command {
    let mut cmd = crate::common::lessence();
    cmd.env("LESSENCE_REPORT_DIR", env!("CARGO_TARGET_TMPDIR"));
    cmd
}

#[test]
fn contract_single_thread_via_threads_flag() {
    let mut child = lessence()
        .args(["--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line 1\ntest line 2\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait");

    assert!(
        output.status.success(),
        "Single-threaded execution via --threads 1 should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn contract_removed_flag_error() {
    let mut child = lessence()
        .args(["--single-thread"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait");

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
        stderr.contains("--single-thread") || stderr.contains("single-thread"),
        "Error should mention the rejected flag. Stderr: {stderr}",
    );
}

#[test]
fn contract_invalid_thread_count() {
    let mut child = lessence()
        .args(["--threads", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait");

    assert!(!output.status.success(), "Should fail with thread count 0");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Thread count must be at least 1") || stderr.contains("at least 1"),
        "Error should mention minimum thread count. Stderr: {stderr}"
    );
}

#[test]
fn a_thread_count_above_the_machine_is_capped_and_said_so() {
    let mut child = lessence()
        .args(["--threads", "100000"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"test line 1\n")
        .unwrap();
    let output = child.wait_with_output().expect("Failed to wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("capping --threads 100000 at "),
        "--threads must reach the fold, which caps it at the cores there are: {stderr}"
    );
}

#[test]
fn contract_multi_thread_unchanged() {
    let mut child = lessence()
        .args(["--threads", "4"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"test line 1\ntest line 2\ntest line 3\n")
            .ok();
    }

    let output = child.wait_with_output().expect("Failed to wait");

    assert!(
        output.status.success(),
        "Multi-threaded execution should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn contract_auto_detect_unchanged() {
    let mut child = lessence()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test line 1\ntest line 2\n").ok();
    }

    let output = child.wait_with_output().expect("Failed to wait");

    assert!(
        output.status.success(),
        "Auto-detect mode should succeed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
