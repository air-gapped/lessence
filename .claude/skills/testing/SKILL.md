---
name: testing
description: >-
  Testing patterns for lessence. Covers running tests, writing tests,
  fuzzing (cargo-fuzz), mutation testing (cargo-mutants), code coverage
  (cargo-llvm-cov), property-based testing (proptest), ReDoS security
  tests, flaky test diagnosis, and performance regression detection.
  Use when: "add tests", "run tests", "test coverage", "mutation testing",
  "fuzz", "flaky test", "ReDoS", "evil pattern", "scaling test".
---

# Testing lessence

## Running Tests

```bash
cargo test --lib              # Unit tests only (fast, <2s)
cargo nextest run --release   # Full suite in release mode (CI)
make ci                       # Full CI pipeline (fmt + clippy + test + deny)
```

## Test Speed Rules

Tests must be fast. Slow tests break mutation testing, annoy developers,
and hide behind CI where no one watches them.

1. Never use absolute wall-clock assertions (`< 100ms`). Use scaling-ratio
   tests instead — measure at input size N and 4N, assert ratio < 8.0.
   This tests algorithmic complexity and is immune to CPU contention.
2. Skip expensive operations in debug builds via `cfg!(debug_assertions)`.
   Processing 70k lines through a debug binary takes 50s vs 2s in release.
   The compression ratio is identical — only speed differs.
3. Use `env!("CARGO_BIN_EXE_lessence")` in integration tests, never
   `./target/release/lessence`. The hardcoded path breaks under cargo-mutants
   and ties tests to a specific build profile.
4. Timing-sensitive tests run in a nextest serial group (`.config/nextest.toml`)
   with `max-threads = 1` to eliminate CPU contention flakes.

## Writing Tests

### Unit Tests (in src/)

Private functions need tests inside `#[cfg(test)] mod tests` in the same file.
Use the `make_line` / `make_group` helpers in `src/folder.rs` to build synthetic
`PatternGroup` values for rollup and folding tests.

### Integration Tests (in tests/)

Use `env!("CARGO_BIN_EXE_lessence")` to find the binary:

```rust
let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
    .args(["--no-stats", "--threads", "1"])
    .stdin(std::fs::File::open("tests/fixtures/sample.log").unwrap())
    .output()
    .expect("failed to run lessence");
```

Tests in subdirectories need `[[test]]` entries in `Cargo.toml`.

### Folding Tests

Use 4+ similar lines to verify compression (min-collapse default is 3).
Assert on the presence of `"similar"` in output, not specific line counts.

### ReDoS / Security Tests (scaling-ratio pattern)

Test algorithmic complexity, not absolute speed:

```rust
fn assert_linear_scaling(label: &str, make_input: impl Fn(usize) -> String) {
    let small = make_input(1);
    let large = make_input(4);
    let iters = 2000;
    let time_small = measure(&small, iters);
    let time_large = measure(&large, iters);
    let ratio = time_large.as_nanos() as f64 / time_small.as_nanos().max(1) as f64;
    assert!(ratio < 8.0,
        "{label}: ratio {ratio:.1}x for 4x input (quadratic would be ~16.0)");
}
```

Linear (O(n)) → ratio ≈ 4.0. Quadratic (ReDoS) → ratio ≈ 16.0.
Threshold 8.0 gives 2x headroom for noise.

### Synthetic Log Generator

`tests/fixtures/log_generator.rs` generates deterministic kubelet-style logs
at configurable sizes. Use for constitutional compliance tests instead of
depending on gitignored corpus files:

```rust
#[path = "../fixtures/log_generator.rs"]
mod log_generator;

let input = log_generator::generate_log(1000); // 98.5% compression
```

## Heavy Testing (Local Only)

These run outside CI. See `make help` for all targets.

```bash
make fuzz                     # Fuzz normalizer (nightly, 5 min default)
make fuzz FUZZ_WORKERS=8      # Parallel fuzzing on 8 cores
make fuzz-fold                # Fuzz full folding pipeline
make mutants                  # Mutation testing, full suite (~hours)
make mutants-quick            # Mutation testing, unit tests only (~40 min)
make coverage                 # HTML code coverage report
```

### Fuzzing (cargo-fuzz)

Requires nightly: `rustup toolchain install nightly && cargo install cargo-fuzz`.
Two fuzz targets in `fuzz/fuzz_targets/`: `fuzz_normalize` (pattern detectors)
and `fuzz_fold` (full pipeline). Corpus persists between runs.

### Mutation Testing (cargo-mutants)

Runs with `systemd-run --scope -p MemoryMax=16G` to prevent OOM.
Default 2 parallel jobs, 30s timeout per mutant.

Interpret results: "missed" means a mutant survived — either no test covers
that code path, or the test doesn't assert tightly enough. With `--lib`
(quick mode), integration-only code shows as missed — that's expected.

### Code Coverage (cargo-llvm-cov)

```bash
make coverage    # HTML report at target/llvm-cov/html/index.html
```

Uses `--no-fail-fast` so timing test failures under instrumentation
don't block the report.

## Test Organization

```
tests/
  unit/              # Pattern detector unit tests
  integration/       # CLI and end-to-end tests
  contract/          # API contract tests
  security/          # ReDoS scaling tests
  property/          # Property-based tests (proptest)
  snapshot/          # Output snapshot tests (insta)
  benchmarks/        # Detection performance scaling tests
  fixtures/          # Test data + log_generator.rs
.config/nextest.toml # Serial group for timing-sensitive tests
```

## Nextest Configuration

`.config/nextest.toml` defines a `serial-timing` test group that runs
timing-sensitive tests with `max-threads = 1`. Filter pattern:

```
test(redos) | test(scales_linearly) | test(performance) | ...
```

This eliminates flakes from CPU contention in parallel test runs.
