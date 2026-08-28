//! Complexity guards for the folding pipeline.
//!
//! Every performance bug this project has actually shipped was a complexity
//! bug, not a constant-factor one: `finish()` draining with `remove(0)`
//! (lessence-aw4), the key-value detector's per-match context decisions
//! (lessence-lsu), `resolve_overlaps` (lessence-pow), the preflight analyzer
//! (lessence-tgv). A wall-clock budget cannot see those — a quadratic path is
//! fast on a small input and only explodes in production.
//!
//! So these do not time anything absolute. They run each shape at N and 4N and
//! assert the ratio stays near 4. Linear passes, quadratic (~16x) fails, and
//! the whole file finishes in well under a second on any machine.

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

/// Build `n` lines from a per-line template.
fn lines(n: usize, f: impl Fn(usize) -> String) -> String {
    (0..n).map(f).collect::<Vec<_>>().join("\n")
}

#[test]
fn distinct_lines_scales_linearly() {
    // lessence-aw4: every line founds its own group, so the group buffer grows
    // with the input. Both the similarity scan and the final drain are on the
    // hook here — this is the shape that made `finish()` quadratic.
    let build = |n| {
        lines(n, |i| {
            format!("2025-01-01T00:00:00Z unrelated event {i} on subject {i}")
        })
    };
    let small = build(100);
    let large = build(400);
    crate::common::assert_linear_scaling("fold_distinct_lines", &small, &large, fold);
}

#[test]
fn repeated_lines_scales_linearly() {
    // The happy path: one group, every line resolving through the exact-hash
    // index rather than the linear scan.
    let build = |n| {
        lines(n, |i| {
            format!("2025-01-01T00:00:00Z request served in {} ms", i % 7)
        })
    };
    let small = build(200);
    let large = build(800);
    crate::common::assert_linear_scaling("fold_repeated_lines", &small, &large, fold);
}

#[test]
fn many_key_value_pairs_on_one_line_scales_linearly() {
    // lessence-lsu and the long-key=value stall: context decisions used to be
    // recomputed inside the per-match closure, once per pair.
    let build = |pairs| {
        let kv = (0..pairs)
            .map(|i| format!("field{i}=value{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines(20, |_| format!("2025-01-01T00:00:00Z config applied {kv}"))
    };
    let small = build(25);
    let large = build(100);
    crate::common::assert_linear_scaling("fold_key_value_density", &small, &large, fold);
}

#[test]
fn many_timestamps_on_one_line_scales_linearly() {
    // lessence-pow: resolve_overlaps kept a growing interval set per line.
    let build = |stamps| {
        let ts = (0..stamps)
            .map(|i| format!("2025-01-01T00:{:02}:00Z", i % 60))
            .collect::<Vec<_>>()
            .join(" ");
        lines(20, |_| format!("window {ts}"))
    };
    let small = build(20);
    let large = build(80);
    crate::common::assert_linear_scaling("fold_timestamp_density", &small, &large, fold);
}

#[test]
fn structured_records_scales_linearly_in_field_count() {
    // The shape lessence-8jb was measured on: a wide compact-JSON record whose
    // every value is a token. Widening the record must not cost quadratically.
    let build = |fields| {
        let body = (0..fields)
            .map(|i| format!("\"key_{i}\":\"value-{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        lines(20, |i| format!("{{\"seq\":{i},{body}}}"))
    };
    let small = build(20);
    let large = build(80);
    crate::common::assert_linear_scaling("fold_record_width", &small, &large, fold);
}

#[test]
fn long_records_past_the_similarity_cap_scales_linearly() {
    // lessence-fo2 territory: past MAX_SIMILARITY_TOKENS the comparison changes
    // strategy. The multiset path must stay linear in tokens, not quadratic.
    let build = |n| {
        let tail = (0..120)
            .map(|i| format!("f{i}=v{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines(n, |i| format!("evt state=s{} {tail}", i % 5))
    };
    let small = build(40);
    let large = build(160);
    crate::common::assert_linear_scaling("fold_long_records", &small, &large, fold);
}

#[test]
fn repeated_quoted_values_scales_linearly() {
    // The quoted-string cascade is memoized per distinct value; a corpus that
    // repeats a small vocabulary must not pay the cascade every time.
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
    crate::common::assert_linear_scaling("fold_quoted_reuse", &small, &large, fold);
}

/// The guard above is only worth having if it fires. Feed the same helper a
/// deliberately quadratic function and assert it fails — otherwise a rewrite
/// that loosens the threshold would silently disarm every test in this file.
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
         this file are not actually guarding anything"
    );
}
