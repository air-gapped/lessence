//! Fold-integrity regressions found by audit: a line is never dropped, the
//! shown last line does not depend on the thread count, and the JSON and
//! text modes agree on what folding saved. All input is invented.

use std::io::Write;
use std::process::Stdio;

fn run_lessence(args: &[&str], input: &str) -> std::process::Output {
    let mut child = crate::common::lessence()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lessence");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let out = child.wait_with_output().expect("wait");
    writer.join().unwrap();
    out
}

fn stdout(args: &[&str], input: &str) -> String {
    let out = run_lessence(args, input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Three-letter syllable words: plain words no detector tokenises.
fn word(i: usize) -> String {
    const SYL: [&str; 12] = [
        "ba", "ko", "ri", "mu", "te", "so", "la", "vi", "ne", "pu", "da", "fe",
    ];
    format!(
        "{}{}{}",
        SYL[i % 12],
        SYL[(i / 12) % 12],
        SYL[(i / 144) % 12]
    )
}

#[test]
fn evicted_group_below_min_collapse_keeps_every_line() {
    // Five identical lines, then enough distinct ones to evict their group
    // from the 1,000-group live buffer. The group never reaches
    // --min-collapse 10, so it renders line by line and none may be cut.
    let mut input = String::new();
    for _ in 0..5 {
        input.push_str("heartbeat missed from upstream\n");
    }
    for i in 0..1200 {
        input.push_str(&format!(
            "{} {} {} done\n",
            word(i),
            word(i * 7 + 3),
            word(i * 13 + 5)
        ));
    }
    for threads in ["1", "4"] {
        let text = stdout(
            &[
                "--no-report",
                "-q",
                "--threads",
                threads,
                "--min-collapse",
                "10",
            ],
            &input,
        );
        assert_eq!(
            text.matches("heartbeat missed from upstream").count(),
            5,
            "--threads {threads} must print all five lines"
        );
    }
}

#[test]
fn shown_last_line_does_not_depend_on_thread_count() {
    // Three distinct shapes founded in order that later converge on one
    // template: which member ends the merged group must come from the true
    // line order, not from the batch the parallel path reads in.
    let input = "\
[pod/probe-6c9d-abcde/probe] {\"cluster-name\":\"alder/alder-db\",\"level\":\"debug\",\"msg\":\"+    imageName: registry.example.test/vessel-9:1.2-p3,\",\"pkg\":\"cluster\",\"time\":\"2026-02-01T05:07:25Z\"}
[pod/probe-6c9d-abcde/probe] {\"cluster-name\":\"alder/alder-db\",\"level\":\"debug\",\"msg\":\"+          sideImage: registry.example.test/vessel-9:1.2-p3,\",\"pkg\":\"cluster\",\"time\":\"2026-02-01T05:07:26Z\"}
[pod/probe-6c9d-abcde/probe] {\"cluster-name\":\"alder/alder-db\",\"level\":\"debug\",\"msg\":\"-              limit: 1Gi\",\"pkg\":\"cluster\",\"time\":\"2026-02-01T05:43:30Z\"}
[pod/probe-6c9d-abcde/probe] {\"cluster-name\":\"alder/alder-db\",\"level\":\"debug\",\"msg\":\"+              limit: 2Gi\",\"pkg\":\"cluster\",\"time\":\"2026-02-01T05:43:31Z\"}
";
    let one = stdout(&["--no-report", "-q", "--threads", "1"], input);
    let four = stdout(&["--no-report", "-q", "--threads", "4"], input);
    assert_eq!(one, four, "text output must not depend on --threads");
    assert!(
        one.contains("→ 2026-02-01T05:43:31Z"),
        "the marker's range ends at the true last line: {one}"
    );
}

#[test]
fn repeating_a_known_value_at_the_cap_is_not_capped() {
    // 64 distinct addresses fill the set; the 65th line repeats one. No
    // value was lost, so the entry is neither capped nor incomplete.
    let mut input = String::new();
    for i in 0..64 {
        input.push_str(&format!("connect to 10.0.0.{} failed\n", i + 1));
    }
    input.push_str("connect to 10.0.0.1 failed\n");
    for threads in ["1", "4"] {
        let text = stdout(&["--format", "json", "--threads", threads], &input);
        let group: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let ip = &group["variation"]["IPV4"];
        assert_eq!(ip["distinct_count"], 64, "--threads {threads}");
        assert_eq!(ip["capped"], false, "--threads {threads}");
    }
}

#[test]
fn essence_lines_saved_agrees_between_text_and_json() {
    let mut input = String::new();
    for i in 0..9 {
        input.push_str(&format!("probe alpha finished step {}\n", i % 3));
    }
    for _ in 0..4 {
        input.push_str("probe beta restarted unit\n");
    }
    let stats = run_lessence(
        &["--essence", "--no-report", "--stats-json", "--threads", "1"],
        &input,
    );
    let from_text: serde_json::Value =
        serde_json::from_slice(stats.stderr.split(|b| *b == b'\n').next().unwrap()).unwrap();
    let json = stdout(&["--essence", "--format", "json", "--threads", "1"], &input);
    let summary: serde_json::Value = serde_json::from_str(json.lines().last().unwrap()).unwrap();
    assert!(from_text["lines_saved"].as_u64().unwrap() > 0);
    assert_eq!(from_text["lines_saved"], summary["lines_saved"]);
}
