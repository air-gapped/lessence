use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

#[test]
fn test_top_n_shows_exactly_n_groups() {
    let output = lessence_bin()
        .args(["--top", "2", "--no-stats", "tests/fixtures/nginx_sample.log"])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Count groups by counting [Nx] prefixes
    let group_count = stdout.lines().filter(|l| l.starts_with('[') && l.contains("x]")).count();
    assert_eq!(group_count, 2, "Should show exactly 2 groups. Got:\n{}", stdout);
}

#[test]
fn test_top_n_sorted_descending() {
    let output = lessence_bin()
        .args(["--top", "5", "--no-stats", "tests/fixtures/nginx_sample.log"])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract counts from [Nx] prefixes
    let counts: Vec<usize> = stdout
        .lines()
        .filter_map(|l| {
            if l.starts_with('[') && l.contains("x]") {
                l.trim_start_matches('[')
                    .split('x')
                    .next()
                    .and_then(|n| n.parse().ok())
            } else {
                None
            }
        })
        .collect();

    assert!(!counts.is_empty(), "Should have count prefixes");
    for i in 1..counts.len() {
        assert!(
            counts[i - 1] >= counts[i],
            "Counts should be descending: {:?}",
            counts
        );
    }
}

#[test]
fn test_top_n_larger_than_groups_shows_all() {
    let output = lessence_bin()
        .args(["--top", "100", "--no-stats", "tests/fixtures/nginx_sample.log"])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Should produce output even when N > total groups");

    // Coverage footer should show on stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("showing top"),
        "Should show coverage footer on stderr. Got: {}",
        stderr
    );
}

#[test]
fn test_without_top_output_unchanged() {
    // Without --top, output should be chronological (no [Nx] prefixes)
    let output = lessence_bin()
        .args(["--no-stats", "tests/fixtures/nginx_sample.log"])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let has_count_prefix = stdout.lines().any(|l| l.starts_with('[') && l.contains("x]"));
    assert!(!has_count_prefix, "Without --top, should not have [Nx] count prefixes");
}

#[test]
fn test_top_n_with_stdin() {
    let mut child = lessence_bin()
        .args(["--top", "2", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        // Write lines that will create 3 groups with different frequencies
        for _ in 0..10 {
            writeln!(stdin, "ERROR connection refused to 10.0.0.1:8080").ok();
        }
        for _ in 0..5 {
            writeln!(stdin, "WARN timeout after 30s on request abc-123").ok();
        }
        for _ in 0..2 {
            writeln!(stdin, "INFO startup complete in 1.5s").ok();
        }
    }
    let output = child.wait_with_output().expect("Failed to read output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let group_count = stdout.lines().filter(|l| l.starts_with('[') && l.contains("x]")).count();
    assert_eq!(group_count, 2, "Should show exactly 2 groups from stdin. Got:\n{}", stdout);
}

#[test]
fn test_top_n_coverage_footer() {
    let output = lessence_bin()
        .args(["--top", "1", "--no-stats", "tests/fixtures/nginx_sample.log"])
        .output()
        .expect("Failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("showing top 1 of"),
        "Footer should show 'showing top 1 of N patterns'. Got: {}",
        stderr
    );
    assert!(
        stderr.contains("% of input lines"),
        "Footer should show coverage percentage. Got: {}",
        stderr
    );
}
