use std::fs::File;
use std::time::{Duration, Instant};

/// Open a gitignored `examples/distilled/` corpus a test depends on. `None` means "print
/// a skip line and return" — the caller does the returning. Silently passing
/// when the file is absent is how a gate stops proving anything without
/// anyone noticing, so this panics naming the missing path unless `CI` is set
/// (GitHub runners carry no corpora and are expected to skip).
#[allow(dead_code)] // only integration.rs uses this; security.rs and misc.rs share the module
pub fn require_example(path: &str) -> Option<File> {
    match File::open(path) {
        Ok(f) => Some(f),
        Err(e) if std::env::var_os("CI").is_some() => {
            eprintln!("Skipping: {path} not available ({e}) — CI has no corpora");
            None
        }
        Err(e) => panic!("{path} is required for this test and could not be opened: {e}"),
    }
}

/// Assert that a function scales linearly (O(n)) with input size.
///
/// Measures execution at size N (small) and 4N (large). Linear scaling
/// gives a ratio of ~4.0; quadratic gives ~16.0. Threshold of 8.0 gives
/// 2x headroom for noise while catching O(n²) regressions.
///
/// Uses median-of-3 measurements to eliminate single-spike outliers
/// from background processes and CPU contention. Combined with nextest
/// retries (2 attempts) and serial execution, this makes flakes
/// vanishingly rare while still catching genuine regressions.
pub fn assert_linear_scaling<F: Fn(&str)>(label: &str, small: &str, large: &str, f: F) {
    // Warmup — settle allocator and caches
    for _ in 0..20 {
        f(small);
        f(large);
    }

    // Auto-calibrate: find iteration count where small runs >= 5ms
    let mut iters: u64 = 100;
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            f(small);
        }
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(5) || iters >= 100_000 {
            break;
        }
        iters *= 4;
    }

    // Median-of-3: run the measurement 3 times, take the middle ratio.
    // This eliminates single-spike outliers from background processes.
    let mut ratios = [0.0f64; 3];
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
    let median = ratios[1]; // middle of 3

    assert!(
        median < 8.0,
        "{label}: 4x input took {median:.1}x median (expected ~4.0, quadratic would be ~16.0). \
         iters={iters}, all_ratios=[{:.1}, {:.1}, {:.1}]",
        ratios[0],
        ratios[1],
        ratios[2],
    );
}

/// How many corpora a sweep works on at once.
///
/// The per-corpus work in a sweep is a subprocess: roughly 30 ms of fork,
/// exec and dynamic linking around 10 ms of folding, so a serial sweep over
/// eighty corpora spends most of its wall clock in the kernel with one core
/// busy.
///
/// Two, not more, and the reason is not caution. The suite also holds
/// wall-clock ratio tests (`assert_linear_scaling`), and they share the
/// machine. Measured over the whole suite on this hardware: serial sweeps
/// 12.5 s and no retries, two 8.9 s and no retries, three 7.8 s and four
/// 7.25 s — but three and four made `test_no_match_performance` fail its
/// first attempt on *every* run, passing only on nextest's retry. A test
/// that always needs a retry is not flaky, it is failing quietly, and 1.6
/// seconds is not worth buying with that.
pub const CORPUS_SWEEP_THREADS: usize = 2;

/// Run `f` over every corpus, at most [`CORPUS_SWEEP_THREADS`] at a time.
///
/// `f` must assert rather than return: a panic in a worker propagates when
/// the scope joins, so a failing corpus still fails the test.
#[allow(dead_code)] // integration.rs uses this; the other harnesses share the module
pub fn sweep_corpora<T: Sync>(corpora: &[T], f: impl Fn(&T) + Sync) {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let f = &f;
    let next = &next;
    std::thread::scope(|scope| {
        for _ in 0..CORPUS_SWEEP_THREADS.min(corpora.len().max(1)) {
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(corpus) = corpora.get(i) else { return };
                    f(corpus);
                }
            });
        }
    });
}
