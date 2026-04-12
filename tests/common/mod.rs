use std::time::{Duration, Instant};

/// Assert that a function scales linearly (O(n)) with input size.
///
/// Measures execution at size N (small) and 4N (large). Linear scaling
/// gives a ratio of ~4.0; quadratic gives ~16.0. Threshold of 8.0 gives
/// 2x headroom for noise while catching O(n²) regressions.
///
/// Automatically scales iteration count so the small input runs for at
/// least 5ms, eliminating noise on fast CPUs and with opt-level>0.
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

    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;
    assert!(
        ratio < 8.0,
        "{label}: 4x input took {ratio:.1}x (expected ~4.0, quadratic would be ~16.0). \
         iters={iters}, small={small_ns}ns, large={large_ns}ns",
        small_ns = time_small.as_nanos() / u128::from(iters),
        large_ns = time_large.as_nanos() / u128::from(iters),
    );
}
