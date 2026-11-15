use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lessence::{Config, PatternFolder};
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

fn rayon_auto_thread_count_config() -> Config {
    Config {
        thread_count: None,
        ..Default::default()
    }
}

fn run_parallel_e2e(content: &str) -> Vec<String> {
    let mut folder = PatternFolder::new(rayon_auto_thread_count_config());
    let mut outputs = Vec::new();
    for line in content.lines() {
        let _ = folder.process_line(line);
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

fn criterion_honouring_cli_baseline_flags() -> Criterion {
    Criterion::default().configure_from_args()
}

criterion_group! {
    name = benches;
    config = criterion_honouring_cli_baseline_flags();
    targets = bench_folder_parallel_e2e
}
criterion_main!(benches);
