use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

#[test]
fn test_fit_implies_summary() {
    // --fit should produce summary-style output ([Nx] prefixes) even without --summary
    let input = "error: connection refused\nerror: connection refused\nerror: connection refused\n\
                 warn: timeout reached\nwarn: timeout reached\nwarn: timeout reached\n";

    let mut child = lessence_bin()
        .args(["--fit", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("Failed to wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Summary mode produces [Nx] prefixed lines
    let group_count = stdout
        .lines()
        .filter(|l| l.starts_with('[') && l.contains("x]"))
        .count();
    assert!(
        group_count > 0,
        "--fit should imply --summary with [Nx] prefixes. Got:\n{stdout}"
    );
}

#[test]
fn test_fit_with_top_n_uses_top_n_mode() {
    // --fit --top 2 should show exactly 2 groups (top-N takes priority over implied summary)
    let output = lessence_bin()
        .args([
            "--fit",
            "--top",
            "2",
            "--no-stats",
            "tests/fixtures/nginx_sample.log",
        ])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let group_count = stdout
        .lines()
        .filter(|l| l.starts_with('[') && l.contains("x]"))
        .count();
    assert_eq!(
        group_count, 2,
        "--fit --top 2 should show exactly 2 groups. Got:\n{stdout}"
    );
}

#[test]
fn test_fit_piped_shows_full_output() {
    // When piped (not a terminal), --fit budget is ignored — all patterns shown
    let mut lines = String::new();
    for i in 0..50 {
        for _ in 0..3 {
            lines.push_str(&format!("unique pattern number {i}\n"));
        }
    }

    let mut child = lessence_bin()
        .args(["--fit", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(lines.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("Failed to wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // No truncation indicator when piped
    assert!(
        !stdout.contains("remove --fit for full output"),
        "Piped output should not be truncated. Got:\n{stdout}"
    );
}

#[test]
fn test_fit_with_preflight() {
    // --fit --preflight should produce valid JSON (preflight takes priority)
    let input = "error: something\nerror: something\nerror: something\n";

    let mut child = lessence_bin()
        .args(["--fit", "--preflight"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("Failed to wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Preflight outputs JSON
    assert!(
        stdout.contains('{'),
        "--fit --preflight should still produce JSON. Got:\n{stdout}"
    );
}
