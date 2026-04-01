use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

#[test]
fn test_stats_json_emits_valid_json_on_stderr() {
    let mut child = lessence_bin()
        .args(["--stats-json", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        for i in 0..10 {
            writeln!(stdin, "ERROR connection refused to 10.0.0.{i}:8080").ok();
        }
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|e| panic!("Invalid JSON on stderr: {e}\nContent: {stderr}"));
    assert!(json.is_object(), "Expected JSON object on stderr");
}

#[test]
fn test_no_stats_with_stats_json_still_emits_json() {
    let mut child = lessence_bin()
        .args(["--no-stats", "--stats-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "INFO hello world").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value = serde_json::from_str(&stderr).unwrap_or_else(|e| {
        panic!("--no-stats --stats-json should still emit JSON: {e}\nContent: {stderr}")
    });
    assert!(json["input_lines"].is_number());
}

#[test]
fn test_stats_json_suppresses_human_readable_stats() {
    let mut child = lessence_bin()
        .args(["--stats-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        for _ in 0..5 {
            writeln!(stdin, "ERROR something failed").ok();
        }
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Stdout should not contain the markdown stats footer
    assert!(
        !stdout.contains("lessence Compression Report"),
        "Human stats should not appear on stdout"
    );
    assert!(
        !stdout.contains("Pattern Distribution"),
        "Human stats should not appear on stdout"
    );

    // Stderr should contain JSON, not human-readable stats
    let json: serde_json::Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|e| panic!("Expected JSON on stderr: {e}\nContent: {stderr}"));
    assert!(json.is_object());
}

#[test]
fn test_stats_json_contains_all_required_fields() {
    let mut child = lessence_bin()
        .args(["--stats-json", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        for _ in 0..5 {
            writeln!(stdin, "2024-01-15 10:30:00 ERROR connection refused to 10.0.0.1:8080 uuid=550e8400-e29b-41d4-a716-446655440000").ok();
        }
        writeln!(stdin, "INFO startup complete in 1.5s").ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: serde_json::Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|e| panic!("Invalid JSON: {e}\nContent: {stderr}"));

    // Top-level fields
    assert!(json["input_lines"].is_number(), "Missing input_lines");
    assert!(json["output_lines"].is_number(), "Missing output_lines");
    assert!(
        json["compression_ratio"].is_f64(),
        "Missing compression_ratio"
    );
    assert!(
        json["collapsed_groups"].is_number(),
        "Missing collapsed_groups"
    );
    assert!(json["lines_saved"].is_number(), "Missing lines_saved");
    assert!(
        json["patterns_detected"].is_number(),
        "Missing patterns_detected"
    );
    assert!(json["elapsed_ms"].is_number(), "Missing elapsed_ms");

    // pattern_hits object with all categories (even zero)
    let hits = &json["pattern_hits"];
    assert!(hits.is_object(), "Missing pattern_hits object");
    for field in &[
        "timestamps",
        "ips",
        "hashes",
        "uuids",
        "pids",
        "durations",
        "http_status",
        "sizes",
        "percentages",
        "paths",
        "kubernetes",
        "emails",
    ] {
        assert!(hits[field].is_number(), "Missing pattern_hits.{field}");
    }

    // Verify input_lines is correct
    assert_eq!(json["input_lines"].as_u64().unwrap(), 6);

    // Verify elapsed_ms is present (as_u64 returns Some for non-negative)
    assert!(
        json["elapsed_ms"].as_u64().is_some(),
        "elapsed_ms should be a non-negative integer"
    );
}
