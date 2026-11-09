//! Bad arguments fail cleanly: a usage error is exit 2 with a `lessence:`
//! message, never a hang, a panic, or a silently different run.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> Command {
    crate::common::lessence()
}

/// Run with `input` on stdin; kill and fail if it does not finish in 20 s.
fn run_with_timeout(mut cmd: Command, input: &str) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("lessence did not finish within 20 s (hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run(args: &[&str]) -> std::process::Output {
    let mut cmd = bin();
    cmd.args(args);
    run_with_timeout(cmd, "")
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn log_file(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    let p = dir.path().join("input.log");
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn repeated_stdin_dash_does_not_hang() {
    let mut cmd = bin();
    cmd.args(["--no-report", "-", "-"]);
    let out = run_with_timeout(cmd, "alpha one\nalpha two\nbeta\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("lessence: "),
        "a repeated '-' is announced: {}",
        stderr(&out)
    );
}

#[test]
fn size_overflow_is_a_usage_error_not_a_panic() {
    for flag in ["--max-line-length", "--report-max-bytes"] {
        let out = run(&[flag, "99999999999999999G"]);
        assert_eq!(out.status.code(), Some(2), "{flag}: {}", stderr(&out));
        assert!(!stderr(&out).contains("panicked"), "{}", stderr(&out));
    }
}

#[test]
fn report_max_bytes_zero_is_rejected_up_front() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_file(&dir, "a\nb\nc\n");
    let out = bin()
        .args(["--report-max-bytes", "0"])
        .arg(&log)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--report-max-bytes"),
        "{}",
        stderr(&out)
    );
}

#[cfg(unix)]
#[test]
fn diff_without_a_file_is_a_usage_error() {
    let bin_path = env!("CARGO_BIN_EXE_lessence");
    let out = run(&["--diff", bin_path]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--diff needs a file path"),
        "{}",
        stderr(&out)
    );
    let out = run(&["--diff", bin_path, "-"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--diff needs a file path"),
        "{}",
        stderr(&out)
    );
}

#[cfg(unix)]
#[test]
fn diff_rejects_fold_flags_it_would_ignore() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_file(&dir, "a\nb\nc\n");
    let bin_path = env!("CARGO_BIN_EXE_lessence");
    for flag in [
        &["--threshold", "70"][..],
        &["--min-collapse", "5"],
        &["--disable-patterns", "uuid"],
        &["--frame-continuations"],
        &["--essence"],
        &["--distill"],
    ] {
        let out = bin()
            .args(["--diff", bin_path])
            .args(flag)
            .arg(&log)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag:?}: {}", stderr(&out));
        assert!(stderr(&out).starts_with("lessence: "), "{}", stderr(&out));
        let name = if flag[0] == "--distill" {
            "--diff"
        } else {
            flag[0]
        };
        assert!(stderr(&out).contains(name), "{flag:?}: {}", stderr(&out));
    }
}

#[cfg(unix)]
#[test]
fn diff_error_exits_2_not_1() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_file(&dir, "a\nb\nc\n");
    let out = bin()
        .args(["--diff", "/nonexistent/lessence-old"])
        .arg(&log)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).starts_with("lessence: "), "{}", stderr(&out));
}

#[test]
fn directory_argument_is_skipped_like_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_file(&dir, "alpha\nalpha\nalpha\nalpha\n");
    let out = bin()
        .arg("--no-report")
        .arg(dir.path())
        .arg(&log)
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(err.contains("lessence: "), "{err}");
    assert!(err.contains("Is a directory"), "{err}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("alpha"),
        "the readable file is still folded: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(1), "same status as a missing file");
}

#[test]
fn invalid_format_is_a_usage_error_listing_every_spelling() {
    let out = run(&["--format", "xml"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.starts_with("lessence: "), "{err}");
    assert!(!err.contains("Error: Error"), "{err}");
    for name in ["text", "plain", "markdown", "md", "json", "jsonl"] {
        assert!(err.contains(name), "{name} missing from: {err}");
    }
}

#[test]
fn explain_with_an_explicit_non_json_format_is_rejected() {
    for fmt in ["markdown", "text"] {
        let out = run(&["--explain", "--format", fmt]);
        assert_eq!(out.status.code(), Some(2), "{fmt}: {}", stderr(&out));
        assert!(stderr(&out).starts_with("lessence: "), "{}", stderr(&out));
        assert!(stderr(&out).contains("--explain"), "{}", stderr(&out));
    }
    // --explain alone, and with a JSON format, still works.
    for args in [&["--explain"][..], &["--explain", "--format", "jsonl"]] {
        let mut cmd = bin();
        cmd.args(args);
        let out = run_with_timeout(cmd, "a\nb\nc\n");
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        assert!(String::from_utf8_lossy(&out.stdout).starts_with('{'));
    }
}

#[test]
fn invalid_utf8_names_the_source_and_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("bad.log");
    std::fs::write(&log, b"fine one\nfine two\nbroken \xff\xfe here\n").unwrap();
    let out = bin().arg("--no-report").arg(&log).output().unwrap();
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("bad.log"), "{err}");
    assert!(err.contains("line 3"), "{err}");
    assert!(err.contains("valid UTF-8"), "{err}");
}

#[test]
fn line_limit_notice_carries_the_lessence_prefix() {
    let mut cmd = bin();
    cmd.args(["--no-report", "--max-lines", "2"]);
    let out = run_with_timeout(cmd, "a\nb\nc\nd\n");
    assert!(
        stderr(&out).contains("lessence: Line limit of 2 reached"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn preflight_line_count_matches_the_default_briefing_with_continuations() {
    let input = "a start 1\n  at frame 1\n  at frame 2\nb start 2\n  at frame 3\nc\n";
    let mut cmd = bin();
    cmd.args(["--preflight", "--frame-continuations"]);
    let out = run_with_timeout(cmd, input);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["lines"], input.lines().count());
}
