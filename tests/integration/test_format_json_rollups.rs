fn run_lessence_json(fixture: &str) -> String {
    let output = crate::common::lessence()
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
    const ROLLUP_K_AS_SRC_FOLDER_MOD_DECLARES: usize = 7;

    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (key, entry) in variation {
            let samples = entry["samples"].as_array().unwrap();
            assert!(
                samples.len() <= ROLLUP_K_AS_SRC_FOLDER_MOD_DECLARES,
                "variation[{key}] has {} samples, exceeds K={ROLLUP_K_AS_SRC_FOLDER_MOD_DECLARES}: {entry}",
                samples.len()
            );
        }
    }
}

#[test]
fn variation_samples_are_sorted_lexicographically() {
    const VARIES_ORDERED_BY_COUNT_RAREST_LAST: &str = "VARIES";
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (key, entry) in variation {
            if key == VARIES_ORDERED_BY_COUNT_RAREST_LAST {
                continue;
            }
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
                "variation[{key}] samples not sorted; RollupComputer::compute sorts the \
                 drawn samples so hash iteration order cannot change them: {samples:?}"
            );
        }
    }
}

#[test]
fn count_only_types_have_empty_samples() {
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
                    "{count_only} is a count-only type (cardinality, never values) but got samples: {entry}"
                );
            }
        }
    }
}

#[test]
fn sample_worthy_types_produce_samples_when_distinct_values_exist() {
    let raw = run_lessence_json("tests/fixtures/nginx_sample.log");
    let records = parse_jsonl(&raw);

    const SAMPLE_WORTHY_TYPES: &[&str] = &[
        "VARIES",
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
fn uncapped_samples_never_outnumber_distinct_count() {
    let small_enumerable_groups = "tests/fixtures/microservices.log";
    let raw = run_lessence_json(small_enumerable_groups);
    let records = parse_jsonl(&raw);

    for rec in records.iter().filter(|r| r["type"] == "group") {
        let variation = rec["variation"].as_object().unwrap();
        for (_key, entry) in variation {
            let distinct = entry["distinct_count"].as_u64().unwrap();
            let capped = entry["capped"].as_bool().unwrap();
            let samples = entry["samples"].as_array().unwrap();

            if !capped {
                assert!(
                    (samples.len() as u64) <= distinct,
                    "samples ({}) > distinct_count ({distinct}) with capped=false: \
                     more samples drawn than distinct values exist",
                    samples.len()
                );
            }
        }
    }
}

#[test]
fn rollup_is_deterministic_across_runs() {
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
        "rollup sampling is not deterministic across runs (seed function or drawn-sample order)"
    );
}
