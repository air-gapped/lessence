use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lessence"));
    cmd.arg("--no-stats");
    cmd
}

#[test]
fn test_file_arg_matches_stdin() {
    // File argument should produce identical output to stdin redirection
    let file_output = lessence_bin()
        .arg("tests/fixtures/nginx_sample.log")
        .output()
        .expect("Failed to run with file arg");

    let mut child = lessence_bin()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn for stdin");

    let input = std::fs::read("tests/fixtures/nginx_sample.log").unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&input).ok();
    }
    let stdin_output = child
        .wait_with_output()
        .expect("Failed to read stdin output");

    assert_eq!(
        String::from_utf8_lossy(&file_output.stdout),
        String::from_utf8_lossy(&stdin_output.stdout),
        "File arg and stdin should produce identical output"
    );
}

#[test]
fn test_multiple_files_concatenated() {
    let output = lessence_bin()
        .arg("tests/fixtures/nginx_sample.log")
        .arg("tests/fixtures/microservices.log")
        .output()
        .expect("Failed to run with multiple files");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Should produce output from both files");
}

#[test]
fn test_no_args_reads_stdin() {
    let mut child = lessence_bin()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"hello world\nhello world\nhello world\n")
            .ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello world"), "Should process stdin input");
}

#[test]
fn test_nonexistent_file_warns_and_continues() {
    let output = lessence_bin()
        .arg("tests/fixtures/nginx_sample.log")
        .arg("nonexistent_file.log")
        .output()
        .expect("Failed to run");

    assert!(
        output.status.success(),
        "Should succeed with at least one valid file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent_file.log"),
        "Should warn about missing file on stderr. Got: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "Should still produce output from valid file"
    );
}

#[test]
fn test_all_files_invalid_exits_nonzero() {
    let output = lessence_bin()
        .arg("nonexistent1.log")
        .arg("nonexistent2.log")
        .output()
        .expect("Failed to run");

    assert!(
        !output.status.success(),
        "Should exit non-zero when all files are invalid"
    );
}

#[test]
fn test_dash_reads_stdin() {
    let mut child = lessence_bin()
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"stdin line one\nstdin line two\nstdin line three\n")
            .ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stdin line"), "Dash should read from stdin");
}
