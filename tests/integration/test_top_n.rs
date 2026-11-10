use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    crate::common::lessence()
}

#[test]
fn test_top_n_shows_exactly_n_groups() {
    let output = lessence_bin()
        .args([
            "--top",
            "2",
            "--no-stats",
            "tests/fixtures/nginx_sample.log",
        ])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Count groups by counting [Nx] prefixes
    let group_count = stdout
        .lines()
        .filter(|l| l.starts_with('[') && l.contains("x]"))
        .count();
    assert_eq!(
        group_count, 2,
        "Should show exactly 2 groups. Got:\n{stdout}"
    );
}

#[test]
fn test_top_n_sorted_descending() {
    let output = lessence_bin()
        .args([
            "--top",
            "5",
            "--no-stats",
            "tests/fixtures/nginx_sample.log",
        ])
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
            "Counts should be descending: {counts:?}"
        );
    }
}

#[test]
fn test_top_n_larger_than_groups_shows_all() {
    let output = lessence_bin()
        .args([
            "--top",
            "100",
            "--no-stats",
            "tests/fixtures/nginx_sample.log",
        ])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "Should produce output even when N > total groups"
    );

    // Coverage footer should show on stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("showing top"),
        "Should show coverage footer on stderr. Got: {stderr}"
    );
}

#[test]
fn test_without_top_output_unchanged() {
    // Without --top, output should be chronological (no [Nx] prefixes)
    let output = lessence_bin()
        .args([
            "--no-stats",
            "--no-report",
            "tests/fixtures/nginx_sample.log",
        ])
        .output()
        .expect("Failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let has_count_prefix = stdout
        .lines()
        .any(|l| l.starts_with('[') && l.contains("x]"));
    assert!(
        !has_count_prefix,
        "Without --top, should not have [Nx] count prefixes"
    );
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

    let group_count = stdout
        .lines()
        .filter(|l| l.starts_with('[') && l.contains("x]"))
        .count();
    assert_eq!(
        group_count, 2,
        "Should show exactly 2 groups from stdin. Got:\n{stdout}"
    );
}

#[test]
fn test_top_n_coverage_footer() {
    let output = lessence_bin()
        .args([
            "--top",
            "1",
            "--no-stats",
            "tests/fixtures/nginx_sample.log",
        ])
        .output()
        .expect("Failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("showing top 1 of"),
        "Footer should show 'showing top 1 of N patterns'. Got: {stderr}"
    );
    assert!(
        stderr.contains("% of input lines"),
        "Footer should show coverage percentage. Got: {stderr}"
    );
}

/// 45 lines sharing no token, so each is its own pattern: more than the
/// summary default cap of 30, which is what makes "all" distinguishable.
fn forty_five_distinct_patterns() -> String {
    fn word(n: usize) -> String {
        let a = (b'a' + (n / 26) as u8 % 26) as char;
        let b = (b'a' + (n % 26) as u8) as char;
        format!("{a}{b}{a}{b}x")
    }
    (0..45)
        .map(|i| {
            (0..5)
                .map(|j| word(i * 5 + j))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn run_stdin(args: &[&str], input: &str) -> (String, String) {
    let mut child = lessence_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn count_text_groups(s: &str) -> usize {
    s.lines()
        .filter(|l| l.starts_with('[') && l.contains("x]"))
        .count()
}

fn count_json_groups(s: &str) -> usize {
    s.lines()
        .filter(|l| l.contains("\"type\":\"group\"") || l.contains("\"type\": \"group\""))
        .count()
}

#[test]
fn top_zero_text_shows_every_pattern() {
    let input = forty_five_distinct_patterns();
    let (all, _) = run_stdin(&["--top", "1000", "-q"], &input);
    let (zero, err) = run_stdin(&["--top", "0", "-q"], &input);
    let uncapped = count_text_groups(&all);
    assert!(
        uncapped > 30,
        "fixture must exceed the default cap: {uncapped}"
    );
    assert_eq!(count_text_groups(&zero), uncapped, "got:\n{zero}");
    assert!(
        err.contains(&format!("showing top {uncapped} of {uncapped} patterns")),
        "trailer must report shown == total: {err}"
    );
}

#[test]
fn top_zero_json_emits_every_group() {
    let input = forty_five_distinct_patterns();
    let (all, _) = run_stdin(&["--format", "json", "--top", "1000", "-q"], &input);
    let (zero, _) = run_stdin(&["--format", "json", "--top", "0", "-q"], &input);
    let uncapped = count_json_groups(&all);
    assert!(
        uncapped > 30,
        "fixture must exceed the default cap: {uncapped}"
    );
    assert_eq!(count_json_groups(&zero), uncapped);
}

#[test]
fn top_zero_summary_still_shows_all() {
    let input = forty_five_distinct_patterns();
    let (capped, _) = run_stdin(&["--summary", "-q"], &input);
    let (zero, _) = run_stdin(&["--summary", "--top", "0", "-q"], &input);
    let (big, _) = run_stdin(&["--summary", "--top", "1000", "-q"], &input);
    assert!(zero.lines().count() > capped.lines().count());
    assert_eq!(zero.lines().count(), big.lines().count());
}

/// Sorted (count, first.line_no, last.line_no) of every group record.
fn group_shape(args: &[&str], file: &str) -> Vec<(u64, u64, u64)> {
    let output = lessence_bin()
        .args(["--json", "-q"])
        .args(args)
        .arg(file)
        .output()
        .expect("Failed to run");
    assert!(
        output.status.success(),
        "lessence {args:?} {file} failed: {:?}",
        output.status
    );
    let mut shape: Vec<(u64, u64, u64)> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
        .map(|v| {
            (
                v["count"].as_u64().unwrap(),
                v["first"]["line_no"].as_u64().unwrap(),
                v["last"]["line_no"].as_u64().unwrap(),
            )
        })
        .collect();
    shape.sort_unstable();
    shape
}

/// A display flag must never change the group set: `--top 0` shows exactly
/// the groups the default run does (lessence-mdh: the ranked path skipped
/// the merge of groups that converge on one template, so one template was
/// shown twice).
#[test]
fn test_top_zero_shows_the_same_groups_as_default_on_every_distilled_corpus() {
    let Some(_) = crate::common::require_example("examples/distilled") else {
        return;
    };
    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("examples/distilled must be readable")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    corpora.sort();
    assert!(
        !corpora.is_empty(),
        "examples/distilled/*.log must be non-empty"
    );
    let disagreeing = std::sync::Mutex::new(Vec::new());
    crate::common::sweep_corpora(&corpora, |corpus| {
        let path = corpus.to_str().unwrap();
        let default = group_shape(&[], path);
        let top = group_shape(&["--top", "0"], path);
        if default != top {
            disagreeing.lock().unwrap().push(format!(
                "{path}: default {} groups, --top 0 {} groups",
                default.len(),
                top.len()
            ));
        }
    });
    let mut disagreeing = disagreeing.into_inner().unwrap();
    disagreeing.sort();
    assert!(
        disagreeing.is_empty(),
        "--top 0 changed the group set on:\n{}",
        disagreeing.join("\n")
    );
}

#[test]
fn summary_caps_text_and_json_at_the_same_default() {
    let input = forty_five_distinct_patterns();
    let (text, _) = run_stdin(&["--summary", "-q"], &input);
    let (json, _) = run_stdin(&["--summary", "--format", "json", "-q"], &input);
    assert_eq!(text.lines().count(), 30, "{text}");
    assert_eq!(count_json_groups(&json), 30, "{json}");
}
