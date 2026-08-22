use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

fn run_preflight(input: &str, extra_args: &[&str]) -> serde_json::Value {
    let mut args = vec!["--preflight"];
    args.extend_from_slice(extra_args);
    let mut child = lessence_bin()
        .args(&args)
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
    assert!(output.status.success(), "preflight run must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).expect("preflight must emit valid JSON")
}

fn timestamps(analysis: &serde_json::Value) -> u64 {
    analysis["pattern_distribution"]["timestamps"]
        .as_u64()
        .expect("timestamps must be a number")
}

#[test]
fn preflight_analyzes_colorized_logs_fully() {
    // The preflight loop used to skip escape stripping, unlike the fold and
    // summary loops. All three now share one ingestion path, so a colorized
    // log (CI, kubectl, journalctl) must analyze exactly like its plain
    // equivalent.
    let mut input = String::new();
    for i in 0..100 {
        input.push_str(&format!(
            "\x1b[32m2024-01-01 10:{:02}:{:02}\x1b[0m \x1b[31mERROR\x1b[0m: connection refused\n",
            i / 60,
            i % 60
        ));
    }
    let analysis = run_preflight(&input, &[]);

    assert_eq!(analysis["total_lines"], 100);
    assert_eq!(
        timestamps(&analysis),
        100,
        "preflight must detect every timestamp under ANSI colors, got: {analysis}"
    );
}

#[test]
fn preflight_strips_escape_payloads_like_the_fold_run_would() {
    // A timestamp hidden inside an OSC window-title sequence is terminal
    // noise, not log content. The fold run strips it before analysis, so
    // preflight must forecast on the same sanitized text: zero timestamps.
    // Under --preserve-color both paths analyze the raw bytes instead and
    // the embedded timestamp counts.
    let input = "\x1b]0;2024-01-01 10:00:00\x07ERROR: connection refused\n".repeat(50);

    let stripped = run_preflight(&input, &[]);
    assert_eq!(stripped["total_lines"], 50);
    assert_eq!(
        timestamps(&stripped),
        0,
        "escape-sequence payloads must not be analyzed as log content, got: {stripped}"
    );

    let preserved = run_preflight(&input, &["--preserve-color"]);
    assert_eq!(
        timestamps(&preserved),
        50,
        "--preserve-color must analyze raw bytes, got: {preserved}"
    );
}

#[test]
fn preflight_reports_plain_input_unchanged() {
    let mut input = String::new();
    for i in 0..50 {
        input.push_str(&format!(
            "2024-01-01 10:00:{:02} ERROR: connection refused\n",
            i % 60
        ));
    }
    let analysis = run_preflight(&input, &[]);
    assert_eq!(analysis["total_lines"], 50);
    assert!(
        timestamps(&analysis) > 0,
        "plain timestamps must still be detected"
    );
}
