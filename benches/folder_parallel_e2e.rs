//! Parallel-mode sanity-check benchmark.
//!
//! Same corpus and measurement strategy as `folder_e2e`, but uses the
//! default `thread_count = None` which lets rayon auto-detect CPU count.
//! This exercises the parallel batch path at `src/folder.rs:880` —
//! `parallel_pattern_detection()` inside the rayon thread pool, followed
//! by `sequential_clustering()` on the main thread.
//!
//! The feature under development has all its new work in the sequential
//! flush phase, so the parallel branch should remain flat across phases.
//! This bench is here to catch any inadvertent regression in the parallel
//! join path, not to celebrate parallel speedups.
//!
//! Run with:
//!   cargo bench --bench folder_parallel_e2e -- --save-baseline main-pre-feature

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::{Config, PatternFolder};
use std::hint::black_box;
use std::time::Duration;

/// Same 6-file Tier 1 corpus and slice budget as `folder_e2e` and
/// `folder_streaming_only`. Identical inputs across bench suites ensure
/// comparisons are apples-to-apples.
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

const SLICE_MAX_LINES: usize = 10_000;

fn load_corpus_sliced(relative_path: &str) -> Option<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
    let Ok(content) = std::fs::read_to_string(&path) else {
        eprintln!("Skipping bench input: {path} not available (examples/ is gitignored)");
        return None;
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

/// Parallel config: `thread_count = None` triggers the default rayon
/// auto-detection path in `process_line()`, which batches lines in
/// blocks of 10,000 before running `parallel_pattern_detection()`.
fn parallel_config() -> Config {
    Config {
        thread_count: None,
        ..Default::default()
    }
}

fn run_parallel_e2e(content: &str) -> Vec<String> {
    let mut folder = PatternFolder::new(parallel_config());
    let mut outputs = Vec::new();
    for line in content.lines() {
        if let Ok(Some(output)) = folder.process_line(line) {
            outputs.push(output);
        }
    }
    if let Ok(final_outputs) = folder.finish() {
        outputs.extend(final_outputs);
    }
    black_box(outputs)
}

fn bench_folder_parallel_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("folder_parallel_e2e");
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
            b.iter(|| run_parallel_e2e(input));
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
    targets = bench_folder_parallel_e2e
}
criterion_main!(benches);
