//! Streaming-only throughput benchmark — the subtraction-method `T_stream`.
//!
//! Identical to `folder_e2e` except `min_collapse = usize::MAX`, so
//! `should_collapse()` always returns false and `format_group()` is never
//! invoked from inside `flush_oldest_safe_group()` during the streaming
//! loop. The final `finish()` still flushes everything at the end, but
//! that terminal flush amortises to near-zero on per-byte throughput
//! compared to per-line streaming cost.
//!
//! Why this matters: `T_e2e − T_stream` gives a direct measurement of
//! flush-time cost per byte without needing to expose `PatternGroup` or
//! `format_group()` publicly.
//!
//! The 1000-group `should_flush_buffer()` threshold at `src/folder.rs:439`
//! is the risk: if buffer growth trips it inside the streaming loop,
//! `format_group()` runs anyway and `T_stream` is contaminated. Tier 1 +
//! Tier 2 inputs must stay under that threshold; Phase 1.6 verifies this
//! empirically.
//!
//! Run with:
//!   cargo bench --bench folder_streaming_only -- --save-baseline main-pre-feature

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::{Config, PatternFolder};
use std::hint::black_box;
use std::time::Duration;

/// Same 6-file Tier 1 corpus as `folder_e2e`, sliced to the same line
/// budget. Journalctl is excluded because its pattern density trips the
/// `should_flush_buffer()` cap and would contaminate the measurement.
const TIER1_CORPUS: &[(&str, &str)] = &[
    ("examples/kubelet.log", "kubelet"),
    (
        "examples/argocd_controller_production.log",
        "argocd_controller",
    ),
    (
        "examples/harbor_postgres_primary.log",
        "harbor_postgres_primary",
    ),
    ("examples/openssh_brute_force.log", "openssh_brute_force"),
    (
        "examples/apache_error_production.log",
        "apache_error_production",
    ),
    ("examples/nginx_sample.log", "nginx_sample"),
];

/// Must match the slice size in `folder_e2e.rs` so the subtraction method
/// (T_e2e − T_stream) is apples-to-apples across bench suites.
const SLICE_MAX_LINES: usize = 10_000;

fn load_corpus_sliced(relative_path: &str) -> Option<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => {
            eprintln!("Skipping bench input: {path} not available (examples/ is gitignored)");
            return None;
        }
    };
    let mut out = String::with_capacity(content.len().min(SLICE_MAX_LINES * 512));
    for (i, line) in content.lines().enumerate() {
        if i >= SLICE_MAX_LINES {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

/// Streaming-only config: `min_collapse = usize::MAX` disables in-loop
/// flushes. Single-threaded to keep the measurement deterministic.
fn streaming_only_config() -> Config {
    Config {
        thread_count: Some(1),
        min_collapse: usize::MAX,
        ..Default::default()
    }
}

fn run_streaming_only(content: &str) -> Vec<String> {
    let mut folder = PatternFolder::new(streaming_only_config());
    let mut outputs = Vec::new();
    for line in content.lines() {
        if let Ok(Some(output)) = folder.process_line(line) {
            outputs.push(output);
        }
    }
    // finish() is still called so that terminal state drops deterministically,
    // but the timed region's per-byte cost should be dominated by the
    // streaming loop. Do not skip finish(): leaving state undrained would
    // hide memory allocator effects that belong in the measurement.
    if let Ok(final_outputs) = folder.finish() {
        outputs.extend(final_outputs);
    }
    black_box(outputs)
}

fn bench_folder_streaming_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("folder_streaming_only");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(15));
    group.warm_up_time(Duration::from_secs(3));
    group.noise_threshold(0.02);
    group.significance_level(0.01);

    for (path, name) in TIER1_CORPUS {
        let Some(content) = load_corpus_sliced(path) else {
            continue;
        };
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, input| {
            b.iter(|| run_streaming_only(input));
        });
    }

    group.finish();
}

fn build_criterion() -> Criterion {
    Criterion::default().configure_from_args()
}

criterion_group! {
    name = benches;
    config = build_criterion();
    targets = bench_folder_streaming_only
}
criterion_main!(benches);
