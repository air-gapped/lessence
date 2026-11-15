use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::Config;
use lessence::normalize::Normalizer;
use std::hint::black_box;
use std::time::Duration;

const TIER1_CORPUS: &[(&str, &str)] = &[
    ("examples/distilled/kubelet.log", "kubelet"),
    (
        "examples/distilled/argocd_controller_production.log",
        "argocd_controller",
    ),
    (
        "examples/distilled/harbor_postgres_primary.log",
        "harbor_postgres_primary",
    ),
    (
        "examples/distilled/openssh_brute_force.log",
        "openssh_brute_force",
    ),
    (
        "examples/distilled/apache_error_production.log",
        "apache_error_production",
    ),
    ("examples/distilled/nginx_sample.log", "nginx_sample"),
];

const SAMPLE_LINES: usize = 1000;
const NEWLINE_BYTES: u64 = 1;

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
        .map(|line| line.len() as u64 + NEWLINE_BYTES)
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

fn criterion_honouring_cli_baseline_flags() -> Criterion {
    Criterion::default().configure_from_args()
}

criterion_group! {
    name = benches;
    config = criterion_honouring_cli_baseline_flags();
    targets = bench_normalize_line
}
criterion_main!(benches);
