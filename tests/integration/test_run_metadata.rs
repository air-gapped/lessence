//! Additive run metadata: raw input identity and explicit input omissions.
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(args)
        .args(["--threads", "1", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(input).unwrap();
    c.wait_with_output().unwrap()
}
fn summary(out: &Output) -> Value {
    let s = String::from_utf8_lossy(&out.stdout);
    let records: Vec<Value> = s
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let last = records.last().expect("summary").clone();
    assert_eq!(last["type"], "summary");
    for group in &records[..records.len() - 1] {
        assert_eq!(group["type"], "group");
        for key in ["schema_version", "version", "input_hash", "degraded"] {
            assert!(group.get(key).is_none());
        }
    }
    assert_eq!(
        last["degraded"].as_array().unwrap().is_empty(),
        last["completeness"]["input"]["complete"].as_bool().unwrap()
    );
    last
}
fn meta(v: &Value) -> Value {
    serde_json::json!({"schema_version":v["schema_version"], "version":v["version"], "input_hash":v["input_hash"], "degraded":v["degraded"]})
}

#[test]
fn json_modes_and_preflight_publish_the_same_raw_identity() {
    let input = b"a\r\nb\nlast";
    let base_out = run(&["--json"], input);
    assert!(base_out.status.success());
    let base = summary(&base_out);
    assert_eq!(base["schema_version"], 1);
    assert_eq!(base["version"]["semver"], env!("CARGO_PKG_VERSION"));
    assert!(!base["version"]["build"].as_str().unwrap().is_empty());
    assert!(!base["version"]["target"].as_str().unwrap().is_empty());
    assert!(base["input_hash"]["unavailable_reason"].is_null());
    assert_eq!(base["input_hash"]["value"].as_str().unwrap().len(), 64);
    assert!(base["briefing"].get("version").is_none());
    for args in [
        vec!["--format", "json"],
        vec!["--explain"],
        vec!["--json", "--summary"],
        vec!["--json", "--top", "1"],
        vec!["--json", "--fit"],
    ] {
        let out = run(&args, input);
        assert!(out.status.success());
        assert_eq!(meta(&summary(&out)), meta(&base), "{args:?}");
    }
    let out = run(&["--preflight"], input);
    assert!(out.status.success());
    let pre: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(meta(&pre), meta(&base));
    assert!(pre.get("briefing").is_none());
    for (key, value) in base["briefing"].as_object().unwrap() {
        assert_eq!(&pre[key], value, "{key}");
    }
}

#[test]
fn raw_hash_ignores_paths_but_preserves_source_boundaries_and_newlines() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let stdin = summary(&run(&["--json"], b"a"));
    let file = summary(&run(&["--json", a.to_str().unwrap()], b""));
    assert_eq!(stdin["input_hash"], file["input_hash"]);
    let renamed = dir.path().join("renamed");
    std::fs::rename(&a, &renamed).unwrap();
    assert_eq!(
        file["input_hash"],
        summary(&run(&["--json", renamed.to_str().unwrap()], b""))["input_hash"]
    );
    let two = summary(&run(
        &["--json", renamed.to_str().unwrap(), b.to_str().unwrap()],
        b"",
    ));
    assert_eq!(
        two["input_hash"]["value"],
        "f41c7607fb22f9fd35c32f8e5122448f311a0ecfe5c77ce7e8ed15dc69d19749"
    );
    assert_ne!(
        two["input_hash"],
        summary(&run(&["--json"], b"ab"))["input_hash"]
    );
    assert_ne!(
        stdin["input_hash"],
        summary(&run(&["--json"], b"a\n"))["input_hash"]
    );
    assert_ne!(
        summary(&run(&["--json"], b"a\n"))["input_hash"],
        summary(&run(&["--json"], b"a\r\n"))["input_hash"]
    );
}

#[test]
fn skipped_lines_still_hash_but_truncation_does_not() {
    let input = b"long line\na\n";
    let full = summary(&run(&["--json"], input));
    let skip = summary(&run(&["--json", "--max-line-length", "1"], input));
    assert_eq!(full["input_hash"], skip["input_hash"]);
    assert_eq!(skip["degraded"][0]["code"], "input.overlong_lines_skipped");
    let truncated = summary(&run(&["--json", "--max-lines", "1"], input));
    assert!(truncated["input_hash"]["value"].is_null());
    assert_eq!(truncated["input_hash"]["unavailable_reason"], "max_lines");
    let exact = summary(&run(&["--json", "--max-lines", "1"], b"a\n"));
    assert!(exact["input_hash"]["unavailable_reason"].is_null());
}

#[test]
fn failed_sources_are_counted_and_all_omissions_are_reported_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ok");
    std::fs::write(&f, b"long\na\nb\n").unwrap();
    let m1 = dir.path().join("missing1");
    let m2 = dir.path().join("missing2");
    let args = [
        "--json",
        "--max-lines",
        "2",
        "--max-line-length",
        "1",
        m1.to_str().unwrap(),
        f.to_str().unwrap(),
        m2.to_str().unwrap(),
    ];
    let out = run(&args, b"");
    assert_eq!(out.status.code(), Some(1));
    let v = summary(&out);
    assert_eq!(v["input_hash"]["unavailable_reason"], "failed_sources");
    assert_eq!(
        v["completeness"]["input"]["failed_sources"],
        serde_json::json!({"value":2,"kind":"exact"})
    );
    let codes: Vec<_> = v["degraded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        [
            "input.overlong_lines_skipped",
            "input.max_lines_reached",
            "input.failed_sources"
        ]
    );
    assert_eq!(
        v["degraded"][2]["count"],
        v["completeness"]["input"]["failed_sources"]
    );
    let mut preflight_args = args;
    preflight_args[0] = "--preflight";
    let preflight = run(&preflight_args, b"");
    assert_eq!(preflight.status.code(), Some(1));
    let preflight: Value = serde_json::from_slice(&preflight.stdout).unwrap();
    assert_eq!(meta(&preflight), meta(&v));

    let out = run(&["--json", m1.to_str().unwrap(), m2.to_str().unwrap()], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let out = run(&["--json"], b"\xff");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn sanitization_withholds_identity_without_hiding_degradation() {
    for args in [
        vec!["--json", "--sanitize-pii"],
        vec!["--json", "--sanitize", "host:pseudonym"],
        vec!["--preflight", "--sanitize", "ip"],
    ] {
        let out = run(&args, b"a\n");
        assert!(out.status.success());
        let v = if args[0] == "--preflight" {
            serde_json::from_slice(&out.stdout).unwrap()
        } else {
            summary(&out)
        };
        assert!(v["input_hash"]["value"].is_null());
        assert_eq!(v["input_hash"]["unavailable_reason"], "sanitized");
        assert_eq!(v["degraded"], serde_json::json!([]));
    }
    let v = summary(&run(
        &["--json", "--sanitize-pii", "--max-lines", "1"],
        b"a\nb\n",
    ));
    assert_eq!(v["input_hash"]["unavailable_reason"], "sanitized");
    assert_eq!(v["degraded"][0]["code"], "input.max_lines_reached");
    let out = run(&["--json", "--fail-on-pattern", "a"], b"a\n");
    assert_eq!(out.status.code(), Some(1));
    let v = summary(&out);
    assert!(v["input_hash"]["unavailable_reason"].is_null());
    assert_eq!(v["degraded"], serde_json::json!([]));
}

#[test]
fn framing_and_escape_stripping_do_not_change_raw_identity() {
    let input = b"event\n  frame one\n  frame two\n\x1b[31mnext\x1b[0m\n";
    let plain = summary(&run(&["--json"], input));
    for args in [
        vec!["--json", "--frame-continuations"],
        vec!["--json", "--preserve-color"],
    ] {
        let out = run(&args, input);
        assert!(out.status.success());
        assert_eq!(summary(&out)["input_hash"], plain["input_hash"]);
    }
}
