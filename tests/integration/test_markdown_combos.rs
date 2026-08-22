//! `--format markdown` supports only the default fold output; every
//! other mode must fail loudly instead of silently emitting plain text.

use std::io::Write;
use std::process::{Command, Stdio};

fn run_with_flags(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn lessence");
    // A rejected combination exits before reading stdin, so this write can
    // hit a broken pipe; that is fine — the exit code carries the verdict.
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"error one\nerror two\nerror three\n");
    drop(stdin);
    child
        .wait_with_output()
        .expect("failed to wait on lessence")
}

fn assert_rejected(args: &[&str]) {
    let out = run_with_flags(args);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{args:?} must exit 2, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--format markdown"),
        "stderr must name the conflict: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "no partial output on a rejected combination"
    );
}

#[test]
fn markdown_with_top_is_rejected() {
    assert_rejected(&["--format", "markdown", "--top", "3"]);
}

#[test]
fn markdown_with_summary_is_rejected() {
    assert_rejected(&["--format", "markdown", "--summary"]);
}

#[test]
fn markdown_with_fit_is_rejected() {
    assert_rejected(&["--format", "markdown", "--fit"]);
}

#[test]
fn markdown_with_preflight_is_rejected() {
    assert_rejected(&["--format", "markdown", "--preflight"]);
}

#[test]
fn markdown_alone_still_works() {
    let out = run_with_flags(&["--format", "markdown"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("# Log Analysis"),
        "markdown doc expected: {stdout}"
    );
}
