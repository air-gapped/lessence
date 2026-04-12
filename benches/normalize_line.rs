//! Pattern-detection micro-benchmark.
//!
//! Targets `Normalizer::normalize_line()` directly, bypassing the
//! similarity/grouping logic. Small, cheap, and fast — its purpose is
//! to catch regressions in the pattern-detection hot path that would
//! otherwise be diluted by the folder-level benches.
//!
//! Corpus: the first 1000 lines of each Tier 1 gate file. Different
//! files exercise different pattern detectors (kubernetes for kubelet,
//! postgres for harbor_postgres, etc.).
//!
//! Run with:
//!   cargo bench --bench normalize_line -- --save-baseline main-pre-feature

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::Config;
use lessence::normalize::Normalizer;
use std::hint::black_box;
use std::time::Duration;

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

const SAMPLE_LINES: usize = 1000;

fn load_corpus_sample(relative_path: &str, max_lines: usize) -> Option<Vec<String>> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
    let Ok(content) = std::fs::read_to_string(&path) else {
        eprintln!("Skipping bench input: {path} not available (examples/ is gitignored)");
        return None;
    };
    Some(
        content
            .lines()
            .take(max_lines)
            .map(std::string::ToString::to_string)
            .collect(),
    )
}

fn sample_byte_size(sample: &[String]) -> u64 {
    sample
        .iter()
        .map(|line| line.len() as u64 + 1) // +1 for the newline that would sit between them
        .sum()
}

fn run_normalize(normalizer: &Normalizer, sample: &[String]) -> usize {
    let mut token_count = 0usize;
    for line in sample {
        if let Ok(log_line) = normalizer.normalize_line(line.clone()) {
            token_count += log_line.tokens.len();
        }
    }
    black_box(token_count)
}

fn bench_normalize_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize_line");
    // normalize_line is fast (~1 ms per 1000-line sample), so the default
    // ceremony is fine. Keeping sample_size lower for consistency with the
    // folder benches.
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(2));
    group.noise_threshold(0.02);
    group.significance_level(0.01);

    let normalizer = Normalizer::new(Config::default());

    for (path, name) in TIER1_CORPUS {
        let Some(sample) = load_corpus_sample(path, SAMPLE_LINES) else {
            continue;
        };
        if sample.is_empty() {
            continue;
        }
        group.throughput(Throughput::Bytes(sample_byte_size(&sample)));
        group.bench_with_input(BenchmarkId::from_parameter(name), &sample, |b, input| {
            b.iter(|| run_normalize(&normalizer, input));
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
    targets = bench_normalize_line
}
criterion_main!(benches);
