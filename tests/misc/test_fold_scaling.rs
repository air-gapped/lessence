use lessence::{Config, PatternFolder};

fn fold(text: &str) {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    for line in text.lines() {
        folder.process_line(line).unwrap();
    }
    let _ = folder.finish().unwrap();
}

fn lines(n: usize, f: impl Fn(usize) -> String) -> String {
    (0..n).map(f).collect::<Vec<_>>().join("\n")
}

#[test]
fn distinct_lines_scales_linearly() {
    let build = |n| {
        lines(n, |i| {
            format!("2025-01-01T00:00:00Z unrelated event {i} on subject {i}")
        })
    };
    let small = build(100);
    let large = build(400);
    crate::common::assert_linear_scaling(
        "fold_distinct_lines (lessence-aw4: every line founds its own group, the shape that made finish() quadratic)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn repeated_lines_scales_linearly() {
    let build = |n| {
        lines(n, |i| {
            format!("2025-01-01T00:00:00Z request served in {} ms", i % 7)
        })
    };
    let small = build(200);
    let large = build(800);
    crate::common::assert_linear_scaling(
        "fold_repeated_lines (one group, every line through the exact-hash index)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn many_key_value_pairs_on_one_line_scales_linearly() {
    let build = |pairs| {
        let kv = (0..pairs)
            .map(|i| format!("field{i}=value{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines(20, |_| format!("2025-01-01T00:00:00Z config applied {kv}"))
    };
    let small = build(25);
    let large = build(100);
    crate::common::assert_linear_scaling(
        "fold_key_value_density (lessence-lsu: context decided once per line, not once per pair)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn many_timestamps_on_one_line_scales_linearly() {
    let build = |stamps| {
        let ts = (0..stamps)
            .map(|i| format!("2025-01-01T00:{:02}:00Z", i % 60))
            .collect::<Vec<_>>()
            .join(" ");
        lines(20, |_| format!("window {ts}"))
    };
    let small = build(20);
    let large = build(80);
    crate::common::assert_linear_scaling(
        "fold_timestamp_density (lessence-pow: resolve_overlaps interval set per line)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn structured_records_scales_linearly_in_field_count() {
    let build = |fields| {
        let body = (0..fields)
            .map(|i| format!("\"key_{i}\":\"value-{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        lines(20, |i| format!("{{\"seq\":{i},{body}}}"))
    };
    let small = build(20);
    let large = build(80);
    crate::common::assert_linear_scaling(
        "fold_record_width (lessence-8jb: wide compact-JSON record, every value a token)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn long_records_past_the_similarity_cap_scales_linearly() {
    let build = |n| {
        let tail = (0..120)
            .map(|i| format!("f{i}=v{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines(n, |i| format!("evt state=s{} {tail}", i % 5))
    };
    let small = build(40);
    let large = build(160);
    crate::common::assert_linear_scaling(
        "fold_long_records (lessence-fo2: past MAX_SIMILARITY_TOKENS the multiset comparison)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn repeated_quoted_values_scales_linearly() {
    let build = |n| {
        lines(n, |i| {
            format!(
                r#"2025-01-01T00:00:00Z volume "pvc-data-{}" attached to pod "worker-{}""#,
                i % 5,
                i % 5
            )
        })
    };
    let small = build(200);
    let large = build(800);
    crate::common::assert_linear_scaling(
        "fold_quoted_reuse (quoted-string cascade memoised per distinct value)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn long_lines_of_different_length_scales_linearly() {
    let build = |units: usize| {
        let body: Vec<String> = (0..units).map(|i| format!("w{i}")).collect();
        lines(20, |i| {
            let mut words = body.clone();
            if i % 2 == 1 {
                words.insert(units / 2, "zone=k2/west".to_string());
            }
            format!("evt {}", words.join(" "))
        })
    };
    let small = build(400);
    let large = build(1600);
    crate::common::assert_linear_scaling(
        "fold_long_unequal_lines (lessence-gyp: banded alignment costs line times band)",
        &small,
        &large,
        fold,
    );
}

#[test]
fn quadratic_work_fails_the_scales_linearly_guard() {
    let quadratic = |input: &str| {
        let bytes = input.as_bytes();
        let mut acc = 0u64;
        for i in 0..bytes.len() {
            for j in 0..bytes.len() {
                acc = acc.wrapping_add(u64::from(bytes[i] ^ bytes[j]));
            }
        }
        std::hint::black_box(acc);
    };
    let small = "x".repeat(120);
    let large = "x".repeat(480);

    let caught = std::panic::catch_unwind(|| {
        crate::common::assert_linear_scaling("self_check_quadratic", &small, &large, quadratic);
    });
    assert!(
        caught.is_err(),
        "assert_linear_scaling passed a quadratic function — the complexity guards in \
         this file are not actually guarding anything; every shipped perf bug was a \
         complexity bug a wall clock cannot see (lessence-aw4, lessence-lsu, lessence-pow, \
         lessence-tgv)"
    );
}
