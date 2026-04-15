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
make ci                       # Full CI pipeline (fmt + clippy + doc + build + test + deny)
```

`make ci` runs automatically via `.githooks/pre-push` before every
push — blocks the push on failure. A PostToolUse hook in
`.claude/settings.json` also auto-runs `cargo fmt --all` after any
`.rs` Edit/Write from Claude Code, so fmt drift never accumulates
between commits during a Claude session. These two layers mean
CI rarely fails on lint or fmt unless someone explicitly bypasses
the hooks with `--no-verify`.

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

Tests use a **barrel pattern**. `tests/` has 5 barrel files
(`unit.rs`, `integration.rs`, `contract.rs`, `security.rs`,
`misc.rs`), each of which imports submodules from its same-named
subdirectory via `mod foo;` declarations. Adding a new test means
dropping a `.rs` file into the right subdirectory and adding a
`mod your_test_name;` line to the barrel — not adding a new
`[[test]]` entry to `Cargo.toml`. A separate `[[test]]` entry
creates a separate test binary (one link step per file), which
is exactly the compile-time cost the barrel pattern exists to
avoid. See the comment on the `[[test]]` blocks in `Cargo.toml`.

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
make mutants                  # Mutation testing, unit tests via -C --lib (~40 min)
make mutants-full             # Mutation testing, full suite including integration (~hours)
make coverage                 # HTML code coverage report
```

### Fuzzing (cargo-fuzz)

Requires nightly: `rustup toolchain install nightly && cargo install cargo-fuzz`.
Two fuzz targets in `fuzz/fuzz_targets/`: `fuzz_normalize` (pattern detectors)
and `fuzz_fold` (full pipeline). Corpus persists between runs.

### Mutation Testing (cargo-mutants)

Runs wrapped in `systemd-run --scope -p MemoryMax=$(MUTANTS_MEM_MAX)`
to cap memory (default 48G). The relevant knobs, all overridable on
the `make` command line:

- `MUTANTS_JOBS` (default `8`) — parallel mutant jobs
- `MUTANTS_TIMEOUT_MULT` (default `3`) — timeout multiplier (NOT
  an absolute seconds value; cargo-mutants times a baseline test
  run and uses `baseline × multiplier` as the per-mutant timeout)
- `MUTANTS_MEM_MAX` (default `48G`) — systemd memory cap

Example: `make mutants MUTANTS_JOBS=4 MUTANTS_MEM_MAX=24G` for a
memory-constrained machine.

Interpret results: "missed" means a mutant survived — either no test
covers that code path, or the test doesn't assert tightly enough.
With `-C --lib` (what `make mutants` uses), integration-only code
shows as missed — that's expected, use `make mutants-full` to
include it.

**Structurally equivalent mutants** — mutations that can't change
observable behavior because of an earlier guard or redundant check
— live in `.cargo/mutants.toml` under `exclude_re`. Currently:

- `network.rs:207` — FQDN regex's `\b` anchors already guarantee
  the `contains('.')` / `starts_with` / `ends_with` checks
- `normalize.rs:59` — PathDetector (step 3) replaces `&Event{}`
  before JsonDetector (step 4) can see it, so the `normalize_json`
  guard is structurally unreachable for that input shape
- `normalize.rs:173` — `QuotedStringDetector` has its own
  `if !text.contains('"')` fast path, making the normalizer's
  `|| contains('\'')` branch dead for token emission

If cargo-mutants reports a "missed" mutant on one of those lines,
don't try to kill it — add to the exclusion list if a new equivalent
is found.

### Code Coverage (cargo-llvm-cov)

```bash
make coverage    # HTML report at target/llvm-cov/html/index.html
```

Uses `--no-fail-fast` so timing test failures under instrumentation
don't block the report.

## Test Organization

```
tests/
  unit.rs              # Barrel — pulls in unit/ submodules
  unit/                # Pattern detector unit tests
  integration.rs       # Barrel — pulls in integration/ submodules
  integration/         # CLI and end-to-end tests
  contract.rs          # Barrel — pulls in contract/ submodules
  contract/            # API contract tests
  security.rs          # Barrel — pulls in security/ submodules
  security/            # ReDoS scaling + evil-pattern tests
  misc.rs              # Barrel — pulls in misc/ submodules
  misc/                # Perf/property/snapshot/PII/limits/email tests
  common/mod.rs        # Shared test helpers (imported by barrels)
  fixtures/            # Test data + log_generator.rs
  property/            # Proptest regressions (auto-generated; do not commit)
  snapshot/snapshots/  # Insta snapshot files (committed, reviewed via `insta review`)
.config/nextest.toml   # Serial group + retries for timing tests
.cargo/mutants.toml    # Mutants config + exclude_re for equivalents
```

## Nextest Configuration

`.config/nextest.toml` defines a `serial-timing` test group that runs
timing-sensitive tests with `max-threads = 1`. Filter pattern:

```
test(redos) | test(scales_linearly) | test(performance) | test(timeout)
| test(allocation_consistency) | test(backward_compatibility)
| test(unix_timestamp_penalty)
```

This eliminates flakes from CPU contention in parallel test runs.

Tests in that group also retry up to 2 times with exponential backoff
(500ms → 5s max). Rationale: noise-induced flakes on a busy machine
pass on retry; genuine regressions (e.g. quadratic scaling) fail all
three attempts. If a test is intermittently failing but always passing
on retry, that's noise — leave it. If it fails all three runs, investigate.
