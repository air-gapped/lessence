//! End-to-end throughput benchmark — the canonical perf gate.
//!
//! Measures `PatternFolder::process_line()` loop + `finish()` on the
//! Tier 1 corpus files in single-threaded text mode.
//! `thread_count = Some(1)` is the deterministic control path (see
//! `src/folder.rs:171`).
//!
//! **All inputs are truncated to the first `SLICE_MAX_LINES` lines**
//! (see constant below). This is load-bearing for tolerable bench
//! runtime on big files: `kubelet.log` in particular runs at ~1 MiB/s
//! and would take ~20 seconds per iteration unsliced, making a
//! 50-sample bench take 17+ minutes. A 10k-line slice (~3 MB for
//! kubelet) brings each iteration under 3 seconds and the full bench
//! suite under 20 minutes. The slice is deterministic and consistent
//! across baseline and comparison runs, which is what matters for a
//! regression gate.
//!
//! Run with:
//!   cargo bench --bench folder_e2e -- --save-baseline main-pre-feature
//!   cargo bench --bench folder_e2e -- --baseline main-pre-feature
//!
//! `examples/` is gitignored; missing files are skipped gracefully so
//! the bench never breaks CI on a fresh checkout.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::{Config, PatternFolder};
use std::hint::black_box;
use std::time::Duration;

/// Tier 1 gate corpus — every bench invocation must pass on all of these.
///
/// `epyc_7days_journalctl.log` was considered but dropped: its pattern density
/// is extreme (1000+ distinct groups by line ~5000), which trips the
/// `should_flush_buffer()` cap at `src/folder.rs:439` during streaming and
/// contaminates the subtraction-method measurement. Journalctl coverage is
/// deferred to the Phase 5 manual calibration sweep.
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

/// Deterministic slice size — every bench input is truncated here.
/// Chosen so the largest input (kubelet, ~285 bytes/line) stays under
/// ~3 MB, which keeps per-iteration time at ~3 seconds and lets a
/// sample_size=30 bench finish in ~90 seconds per input.
const SLICE_MAX_LINES: usize = 10_000;

fn load_corpus_sliced(relative_path: &str) -> Option<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
    let Ok(content) = std::fs::read_to_string(&path) else {
        eprintln!("Skipping bench input: {path} not available (examples/ is gitignored)");
        return None;
    };
    // Truncate at line boundary to SLICE_MAX_LINES. Files smaller than
    // the cap are used in full.
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

/// Canonical text-mode config: single-threaded, defaults otherwise.
/// Single-threaded mode is a clean conditional branch in `process_line()`
/// (`src/folder.rs:171`), not a separate code path — ideal as a bench control.
fn canonical_config() -> Config {
    Config {
        thread_count: Some(1),
        ..Default::default()
    }
}

/// Full end-to-end pass: process each line, collect all emitted output.
/// `black_box` on the collected output prevents dead-code elimination of
/// the fold work — otherwise LLVM might prove the output is unused.
fn run_e2e(content: &str) -> Vec<String> {
    let mut folder = PatternFolder::new(canonical_config());
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

fn bench_folder_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("folder_e2e");
    // Variance control — push the noise floor below the 3% gate threshold.
    // sample_size(30) is the compromise: criterion's minimum is 10, default
    // is 100. At 30 samples × ~3s/iter on the biggest sliced input, one
    // bench finishes in ~90 seconds, which makes the full suite ~15 min.
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(15));
    group.warm_up_time(Duration::from_secs(3));
    group.noise_threshold(0.02);
    group.significance_level(0.01);

    // Tier 1: six gate files, each sliced to SLICE_MAX_LINES.
    for (path, name) in TIER1_CORPUS {
        let Some(content) = load_corpus_sliced(path) else {
            continue;
        };
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, input| {
            b.iter(|| run_e2e(input));
        });
    }

    group.finish();
}

fn build_criterion() -> Criterion {
    // `configure_from_args()` is load-bearing — without it, --baseline /
    // --save-baseline / --profile-time CLI overrides are silently ignored.
    Criterion::default().configure_from_args()
}

criterion_group! {
    name = benches;
    config = build_criterion();
    targets = bench_folder_e2e
}
criterion_main!(benches);
