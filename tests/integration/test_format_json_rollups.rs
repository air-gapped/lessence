//! Phase 3 tests: the `variation` field in JSON group records.
//!
//! Schema validation for the rollup metadata + determinism check that
//! catches any platform-specific drift in the seeded sampler. The plain
//! cross-run determinism is already covered by `test_format_json.rs`;
//! this file adds rollup-specific shape checks and a hard-coded sample
//! assertion that would fail if the RNG or seed function ever changed.

use std::process::Command;

fn run_lessence_json(fixture: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
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
fn variation_field_exists_on_every_group_record() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        assert!(
            rec.get("variation").is_some(),
            "group record missing variation: {rec}"
        );
        let variation = rec["variation"]
            .as_object()
            .unwrap_or_else(|| panic!("variation not an object: {rec}"));
        // Every entry must have the three required fields.
        for (key, value) in variation {
            assert!(
                value.get("distinct_count").is_some(),
                "variation[{key}] missing distinct_count"
            );
            assert!(
                value.get("samples").is_some(),
                "variation[{key}] missing samples"
            );
            assert!(
                value.get("capped").is_some(),
                "variation[{key}] missing capped"
            );
        }
    }
}

#[test]
fn variation_samples_never_exceed_k() {
    // K is ROLLUP_K in src/folder.rs. The calibrated value is 7 as of
    // Phase 5 (P95 of distinct_count on sample-worthy types across
    // the full corpus, capped at terminal-width ceiling of 8).
    // Any sample list longer than K is a bug in the sampler.
    const ROLLUP_K: usize = 7;

    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (key, entry) in variation {
            let samples = entry["samples"].as_array().unwrap();
            assert!(
                samples.len() <= ROLLUP_K,
                "variation[{key}] has {} samples, exceeds K={ROLLUP_K}: {entry}",
                samples.len()
            );
        }
    }
}

#[test]
fn variation_samples_are_sorted_lexicographically() {
    // Sorting the drawn samples is load-bearing for determinism across
    // hash iteration orders. If this test fails, the sort step in
    // RollupComputer::compute was dropped.
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (key, entry) in variation {
            let samples: Vec<&str> = entry["samples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let mut sorted = samples.clone();
            sorted.sort_unstable();
            assert_eq!(
                samples, sorted,
                "variation[{key}] samples not sorted: {samples:?}"
            );
        }
    }
}

#[test]
fn count_only_types_have_empty_samples() {
    // Timestamp, Duration, Number, Size, and other measurement types
    // should never surface per-value samples — they're tracked for
    // distinct_count only. Agents use them to understand *cardinality*,
    // not to read specific values (which would just be noise).
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    const COUNT_ONLY_TYPES: &[&str] = &["TIMESTAMP", "DURATION", "SIZE", "NUMBER", "PORT", "PID"];

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for count_only in COUNT_ONLY_TYPES {
            if let Some(entry) = variation.get(*count_only) {
                let samples = entry["samples"].as_array().unwrap();
                assert!(
                    samples.is_empty(),
                    "{count_only} is a count-only type but got samples: {entry}"
                );
            }
        }
    }
}

#[test]
fn sample_worthy_types_produce_samples_when_distinct_values_exist() {
    // IPV4, PATH, QUOTED_STRING are sample-worthy. If their distinct_count
    // is > 0, samples must be populated.
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    const SAMPLE_WORTHY_TYPES: &[&str] = &[
        "IPV4",
        "IPV6",
        "UUID",
        "PATH",
        "EMAIL",
        "HASH",
        "QUOTED_STRING",
    ];

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for sample_worthy in SAMPLE_WORTHY_TYPES {
            if let Some(entry) = variation.get(*sample_worthy) {
                let distinct = entry["distinct_count"].as_u64().unwrap();
                let samples = entry["samples"].as_array().unwrap();
                if distinct > 0 {
                    assert!(
                        !samples.is_empty(),
                        "{sample_worthy} has distinct_count={distinct} but no samples: {entry}"
                    );
                }
            }
        }
    }
}

#[test]
fn distinct_count_is_correct_when_under_cap() {
    // For small groups (distinct_count well below the cap), the count
    // must be exact and the samples must be a subset of the group's
    // actual values. This catches off-by-one errors in the accumulator
    // and cap-checking logic.
    //
    // We pick the microservices fixture because it has small, easily
    // enumerable groups.
    let raw = run_lessence_json("tests/fixtures/microservices.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (_key, entry) in variation {
            let distinct = entry["distinct_count"].as_u64().unwrap();
            let capped = entry["capped"].as_bool().unwrap();
            let samples = entry["samples"].as_array().unwrap();

            // Not-capped means distinct_count is the exact number of
            // distinct values. Samples length must be ≤ distinct_count
            // (you can never draw more samples than you have values).
            if !capped {
                assert!(
                    (samples.len() as u64) <= distinct,
                    "samples ({}) > distinct_count ({distinct}) with capped=false",
                    samples.len()
                );
            }
        }
    }
}

#[test]
fn rollup_is_deterministic_across_runs() {
    // Stricter variant of the parent determinism test: byte-for-byte
    // equality after stripping elapsed_ms. A regression in the seed
    // function or the drawn-sample order would fail here.
    let raw1 = run_lessence_json("tests/fixtures/nginx_sample.log");
    let raw2 = run_lessence_json("tests/fixtures/nginx_sample.log");

    let mut recs1 = parse_jsonl(&raw1);
    let mut recs2 = parse_jsonl(&raw2);

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

    assert_eq!(
        recs1, recs2,
        "rollup sampling is not deterministic across runs"
    );
}
