//! Integration tests for `--format json` JSONL output.
//!
//! Phase 2 scope: schema shape validation, no rollup fields yet. Phase 3
//! will add `variation` field coverage in a separate test file.

use std::process::Command;
use std::str;

/// Run lessence on a fixture and return stdout as a string.
fn run_lessence_json(fixture: &str) -> String {
    // Build once per test invocation. `cargo build --release` is a no-op
    // when already built, so the overhead is minimal.
    let build = Command::new("cargo")
        .args(["build", "--release"])
        .output()
        .expect("failed to run cargo build");
    assert!(build.status.success(), "cargo build failed");

    let output = Command::new("./target/release/lessence")
        .args(["--format", "json", "--threads", "1", fixture])
        .output()
        .expect("failed to run lessence");
    assert!(
        output.status.success(),
        "lessence exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("lessence stdout was not UTF-8")
}

/// Parse a JSONL stream into a Vec<serde_json::Value>.
fn parse_jsonl(raw: &str) -> Vec<serde_json::Value> {
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .unwrap_or_else(|e| panic!("invalid JSON line: {l}\nerror: {e}"))
        })
        .collect()
}

#[test]
fn json_output_is_valid_jsonl_on_nginx_fixture() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);
    assert!(
        records.len() >= 2,
        "expected at least one group record + summary, got {}",
        records.len()
    );

    // Every record must have a "type" field.
    for (i, rec) in records.iter().enumerate() {
        let ty = rec["type"]
            .as_str()
            .unwrap_or_else(|| panic!("record {i} missing type field: {rec}"));
        assert!(
            ty == "group" || ty == "summary",
            "record {i} has invalid type: {ty}"
        );
    }
}

#[test]
fn json_output_has_exactly_one_summary_record_and_it_is_last() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    let summary_count = records.iter().filter(|r| r["type"] == "summary").count();
    assert_eq!(summary_count, 1, "expected exactly one summary record");
    assert_eq!(
        records.last().unwrap()["type"],
        "summary",
        "summary record must be last"
    );
}

#[test]
fn json_group_ids_are_monotonic_starting_from_zero() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    let groups: Vec<&serde_json::Value> = records.iter().filter(|r| r["type"] == "group").collect();

    for (expected, rec) in groups.iter().enumerate() {
        let id = rec["id"]
            .as_u64()
            .unwrap_or_else(|| panic!("group record missing id: {rec}"));
        assert_eq!(
            id as usize, expected,
            "group id sequence broken: expected {expected}, got {id}"
        );
    }
}

#[test]
fn json_group_record_has_required_fields() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        assert!(rec.get("id").is_some(), "missing id: {rec}");
        assert!(rec.get("count").is_some(), "missing count: {rec}");
        assert!(rec.get("normalized").is_some(), "missing normalized: {rec}");
        assert!(
            rec.get("token_types").is_some(),
            "missing token_types: {rec}"
        );
        assert!(rec.get("first").is_some(), "missing first: {rec}");
        assert!(rec.get("last").is_some(), "missing last: {rec}");
        assert!(rec.get("time_range").is_some(), "missing time_range: {rec}");

        // first / last must have line and line_no
        for side in ["first", "last"] {
            let line_ref = &rec[side];
            assert!(
                line_ref["line"].is_string(),
                "{side}.line must be string: {rec}"
            );
            assert!(
                line_ref["line_no"].is_u64(),
                "{side}.line_no must be number: {rec}"
            );
        }

        // token_types must be a sorted array of strings
        let types = rec["token_types"]
            .as_array()
            .unwrap_or_else(|| panic!("token_types not array: {rec}"));
        let strs: Vec<&str> = types.iter().map(|v| v.as_str().unwrap()).collect();
        let mut sorted = strs.clone();
        sorted.sort_unstable();
        assert_eq!(strs, sorted, "token_types not sorted: {strs:?}");
    }
}

#[test]
fn json_summary_record_has_required_fields() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    let summary = records
        .iter()
        .find(|r| r["type"] == "summary")
        .expect("no summary record");

    for field in [
        "input_lines",
        "output_lines",
        "compression_ratio",
        "collapsed_groups",
        "lines_saved",
        "patterns_detected",
        "elapsed_ms",
        "pattern_hits",
    ] {
        assert!(
            summary.get(field).is_some(),
            "summary missing field {field}: {summary}"
        );
    }

    // pattern_hits must be an object with the expected sub-fields
    let hits = summary["pattern_hits"]
        .as_object()
        .expect("pattern_hits not object");
    for field in [
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
        assert!(
            hits.get(field).is_some(),
            "pattern_hits missing field {field}"
        );
    }
}

#[test]
fn json_output_is_deterministic_across_runs() {
    // Run twice, diff everything except elapsed_ms (intentionally non-deterministic).
    let raw1 = run_lessence_json("tests/fixtures/nginx_sample.log");
    let raw2 = run_lessence_json("tests/fixtures/nginx_sample.log");

    let mut recs1 = parse_jsonl(&raw1);
    let mut recs2 = parse_jsonl(&raw2);

    // Strip elapsed_ms from both runs' summary records before comparing.
    for r in &mut recs1 {
        if r["type"] == "summary" {
            r.as_object_mut().unwrap().remove("elapsed_ms");
        }
    }
    for r in &mut recs2 {
        if r["type"] == "summary" {
            r.as_object_mut().unwrap().remove("elapsed_ms");
        }
    }

    assert_eq!(recs1, recs2, "JSON output not deterministic across runs");
}

#[test]
fn json_output_includes_expected_group_count_for_microservices_fixture() {
    // Coherence check: the group count should be > 0 and the sum of group
    // counts should equal input_lines (every input line is in exactly one
    // group).
    let raw = run_lessence_json("tests/fixtures/microservices.log");
    let records = parse_jsonl(&raw);

    let groups: Vec<&serde_json::Value> = records.iter().filter(|r| r["type"] == "group").collect();
    assert!(!groups.is_empty(), "no group records emitted");

    let sum_counts: u64 = groups
        .iter()
        .map(|g| g["count"].as_u64().unwrap_or(0))
        .sum();
    let summary = records.iter().find(|r| r["type"] == "summary").unwrap();
    let input_lines = summary["input_lines"].as_u64().unwrap();

    assert_eq!(
        sum_counts, input_lines,
        "sum of group counts ({sum_counts}) != input_lines ({input_lines}): \
         every input line must appear in exactly one group"
    );
}
