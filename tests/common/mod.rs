#![allow(dead_code)] // Cargo compiles this module into every test harness; each uses a subset.

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub fn lessence() -> Command {
    command(env!("CARGO_BIN_EXE_lessence"))
}

pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("LESSENCE_REPORT_DIR", disk_backed_report_dir_under_target());
    cmd
}

fn disk_backed_report_dir_under_target() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        // /tmp is a tmpfs on most Linux systems.
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-reports");
        std::fs::create_dir_all(&base).expect("test report directory");
        tempfile::Builder::new()
            .prefix("spawned-")
            .tempdir_in(&base)
            .expect("test report directory")
            .keep()
    })
}

const ENV_SET_ON_CI_RUNNERS_WITHOUT_CORPORA: &str = "CI";

pub fn require_example(path: &str) -> Option<File> {
    match File::open(path) {
        Ok(f) => Some(f),
        Err(e) if std::env::var_os(ENV_SET_ON_CI_RUNNERS_WITHOUT_CORPORA).is_some() => {
            eprintln!("Skipping: {path} not available ({e}) — CI has no corpora");
            None
        }
        Err(e) => panic!("{path} is required for this test and could not be opened: {e}"),
    }
}

const WARMUP_ROUNDS: usize = 20;
const MIN_CALIBRATED_SMALL_RUN: Duration = Duration::from_millis(5);
const MAX_CALIBRATED_ITERATIONS: u64 = 100_000;
const MEASUREMENTS_FOR_MEDIAN: usize = 3;
const LINEAR_RATIO_CEILING_BELOW_QUADRATIC: f64 = 8.0;

pub fn assert_linear_scaling<F: Fn(&str)>(label: &str, small: &str, large: &str, f: F) {
    for _ in 0..WARMUP_ROUNDS {
        f(small);
        f(large);
    }

    let mut iters: u64 = 100;
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            f(small);
        }
        let elapsed = start.elapsed();
        if elapsed >= MIN_CALIBRATED_SMALL_RUN || iters >= MAX_CALIBRATED_ITERATIONS {
            break;
        }
        iters *= 4;
    }

    let mut ratios = [0.0f64; MEASUREMENTS_FOR_MEDIAN];
    for ratio in &mut ratios {
        let start = Instant::now();
        for _ in 0..iters {
            f(small);
        }
        let time_small = start.elapsed();

        let start = Instant::now();
        for _ in 0..iters {
            f(large);
        }
        let time_large = start.elapsed();

        *ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;
    }

    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = ratios[MEASUREMENTS_FOR_MEDIAN / 2];

    assert!(
        median < LINEAR_RATIO_CEILING_BELOW_QUADRATIC,
        "{label}: 4x input took {median:.1}x median (expected ~4.0, quadratic would be ~16.0). \
         iters={iters}, all_ratios=[{:.1}, {:.1}, {:.1}]",
        ratios[0],
        ratios[1],
        ratios[2],
    );
}

pub const CORPUS_SWEEP_THREADS_SHARING_CORES_WITH_TIMING_TESTS: usize = 2;

pub fn sweep_corpora<T: Sync>(corpora: &[T], assert_corpus: impl Fn(&T) + Sync) {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let assert_corpus = &assert_corpus;
    let next = &next;
    std::thread::scope(|scope| {
        for _ in 0..CORPUS_SWEEP_THREADS_SHARING_CORES_WITH_TIMING_TESTS.min(corpora.len().max(1)) {
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(corpus) = corpora.get(i) else { return };
                    assert_corpus(corpus);
                }
            });
        }
    });
}
