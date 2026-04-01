use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

fn run_lessence(input: &str, args: &[&str]) -> (String, String) {
    let mut child = lessence_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).ok();
    }
    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr)
}

#[test]
fn test_folded_output_format() {
    let input = "ERROR connection refused to 10.0.0.1:8080\n\
                 ERROR connection refused to 10.0.0.2:8080\n\
                 ERROR connection refused to 10.0.0.3:8080\n\
                 ERROR connection refused to 10.0.0.4:8080\n\
                 INFO startup complete\n";

    let (stdout, _) = run_lessence(input, &["-q"]);
    insta::assert_snapshot!("folded_output", stdout);
}

#[test]
fn test_top_n_output_format() {
    let input = (0..10)
        .map(|i| format!("ERROR connection refused to 10.0.0.{i}:8080"))
        .chain((0..5).map(|_| "WARN timeout after 30s".to_string()))
        .chain((0..2).map(|_| "INFO startup complete".to_string()))
        .collect::<Vec<_>>()
        .join("\n");

    let (stdout, _) = run_lessence(&input, &["--top", "2", "-q"]);
    insta::assert_snapshot!("top_n_output", stdout);
}

#[test]
fn test_stats_json_format() {
    let input = "ERROR something failed\n\
                 ERROR something failed\n\
                 ERROR something failed\n\
                 INFO all good\n";

    let (_, stderr) = run_lessence(input, &["--stats-json", "-q"]);
    // Parse and re-serialize to normalize field order and remove timing
    let mut json: serde_json::Value = serde_json::from_str(&stderr)
        .expect("stats-json should produce valid JSON");
    // Zero out elapsed_ms since it varies
    json["elapsed_ms"] = serde_json::Value::Number(0.into());
    let normalized = serde_json::to_string_pretty(&json).unwrap();
    insta::assert_snapshot!("stats_json_format", normalized);
}

#[test]
fn test_no_folding_unique_lines() {
    let input = "ERROR database connection failed\n\
                 WARN disk space low on /dev/sda1\n\
                 INFO deployment v2.3.1 started\n";

    let (stdout, _) = run_lessence(input, &["-q"]);
    insta::assert_snapshot!("unique_lines_no_folding", stdout);
}
