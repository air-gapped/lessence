use std::io::Write;
use std::process::{Command, Stdio};

fn lessence_bin() -> Command {
    crate::common::lessence()
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
    analysis["tokens"]
        .as_array()
        .expect("tokens must be an array")
        .iter()
        .find(|t| t["class"] == "timestamps")
        .map_or(0, |t| {
            t["occurrences"]
                .as_u64()
                .expect("occurrences must be a number")
        })
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

    assert_eq!(analysis["lines"], 100);
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
    assert_eq!(stripped["lines"], 50);
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
    assert_eq!(analysis["lines"], 50);
    assert!(
        timestamps(&analysis) > 0,
        "plain timestamps must still be detected"
    );
}

fn run_json_summary(input: &str) -> serde_json::Value {
    let mut child = lessence_bin()
        .args(["--format", "json", "-q"])
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
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["type"] == "summary")
        .expect("summary record")
}

const KLOG_INVENTED: &str = "\
E0412 08:15:01.100001 4242 widget.go:77] frobnicator stalled on shard 17
E0412 08:15:02.100002 4242 widget.go:77] frobnicator stalled on shard 18
E0412 08:15:03.100003 4242 widget.go:77] frobnicator stalled on shard 19
E0412 08:15:04.100004 4242 widget.go:77] frobnicator stalled on shard 20
";

const ISO_INVENTED: &str = "\
2024-04-12T08:15:01Z WARN gizmo queue depth 11 on lane 3
2024-04-12T08:15:02Z WARN gizmo queue depth 12 on lane 3
2024-04-12T08:15:03Z WARN gizmo queue depth 13 on lane 3
2024-04-12T08:15:04Z WARN gizmo queue depth 14 on lane 3
";

#[test]
fn year_inferred_true_for_klog_in_preflight_and_summary() {
    let pre = run_preflight(KLOG_INVENTED, &[]);
    assert_eq!(pre["span"]["year_inferred"], serde_json::Value::Bool(true));
    let sum = run_json_summary(KLOG_INVENTED);
    assert_eq!(
        sum["briefing"]["span"]["year_inferred"],
        serde_json::Value::Bool(true),
        "{sum}"
    );
}

#[test]
fn year_inferred_false_for_iso8601_in_preflight_and_summary() {
    let pre = run_preflight(ISO_INVENTED, &[]);
    assert_eq!(pre["span"]["year_inferred"], serde_json::Value::Bool(false));
    let sum = run_json_summary(ISO_INVENTED);
    assert_eq!(
        sum["briefing"]["span"]["year_inferred"],
        serde_json::Value::Bool(false),
        "{sum}"
    );
}

#[test]
fn year_inferred_absent_without_timestamps() {
    let pre = run_preflight("plain line one\nplain line two\nplain line three\n", &[]);
    assert!(pre["span"].get("year_inferred").is_none(), "{pre}");
}
