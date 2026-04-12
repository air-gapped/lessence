# Benchmarking Lessence

Lessence uses [criterion.rs](https://github.com/bheisler/criterion.rs)
for performance benchmarks. The bench suite is designed as a **local
perf gate**, not a CI gate — `examples/` (the bench corpus) is
gitignored, so CI has no corpus to run against.

When you change hot-path or flush-path code, record a baseline
before the change and compare after. Any regression above **3%** on
text-mode end-to-end throughput is a blocking ship bug. Stretch target
is **0%**.

## Prerequisites

- The `examples/` directory must contain the six Tier 1 corpus files
  (see below). They are gitignored and distributed separately.
- For lowest-noise measurements, run on a quiet machine: close
  browsers, pause background builds, plug in power (disable battery
  throttling), and avoid thermal throttling if possible.

## Bench suite overview

| Bench | Config | Purpose |
|---|---|---|
| `folder_e2e` | `thread_count=Some(1)`, `min_collapse=3` | **Canonical gate.** Full `process_line → finish()` cost, single-threaded text mode. This is the bench whose baseline matters most. |
| `folder_streaming_only` | `thread_count=Some(1)`, `min_collapse=usize::MAX` | Subtraction-method `T_stream`: disables collapsed formatting so per-group flush is minimised. Used with `folder_e2e` to see where regressions land (streaming vs flush). |
| `folder_parallel_e2e` | `thread_count=None` | Parallel-mode sanity check. Same corpus, rayon auto-detect. Catches regressions in the parallel join path. |
| `normalize_line` | per-line `Normalizer::normalize_line` | Pattern-detection micro-bench. Isolates regressions in the normalizer before they dilute folder-level benches. |

All four share the same Tier 1 corpus for apples-to-apples comparison.

## Tier 1 corpus

Six files under `examples/`. Each exercises a different pattern mix:

| File | Size | Coverage |
|---|---|---|
| `kubelet.log` | 20 MB | K8s: UUIDs, paths, kubernetes tokens, high volume |
| `argocd_controller_production.log` | 4 MB | Structured app logs, high token density |
| `harbor_postgres_primary.log` | 7.5 MB | Postgres: duration/timestamp/number-heavy (count-only dominant) |
| `openssh_brute_force.log` | 4 MB | One-template pathological case — stress-tests single-group flush |
| `apache_error_production.log` | 1.9 MB | Apache: brackets, quoted strings |
| `nginx_sample.log` | 6.5 KB | Tiny — fixed-overhead floor |

`epyc_7days_journalctl.log` is **not** in the Tier 1 gate. Its pattern
density (1000+ distinct templates in the first 5k lines) trips the
`should_flush_buffer()` cap at `src/folder.rs:439`, which contaminates
the subtraction method. Journalctl coverage is deferred to the Phase 5
manual sweep (`docs/rollup-calibration.md`).

## Recording a baseline

On a quiet machine:

```bash
cargo bench --bench folder_e2e -- --save-baseline main-pre-feature
cargo bench --bench folder_streaming_only -- --save-baseline main-pre-feature
cargo bench --bench folder_parallel_e2e -- --save-baseline main-pre-feature
cargo bench --bench normalize_line -- --save-baseline main-pre-feature
```

Baselines are stored under `target/criterion/<bench>/<id>/base/` —
gitignored via `target/`.

**For ground-truth baselines**, run the full suite three times across
different machine states (cold cache, warm cache, after a short idle)
and keep the median. Criterion's sample_size=50 and 30s measurement
window handle per-run noise, but machine-level wobble (thermal,
background load) is outside criterion's control.

## Comparing against a baseline

After a change:

```bash
cargo bench --bench folder_e2e -- --baseline main-pre-feature
```

Criterion reports each result as one of:

- `No change in performance detected.` — under the 2% noise threshold.
- `Change within noise threshold.` — statistically plausible noise.
- `Performance has improved.` — green, carry on.
- `Performance has regressed.` — **inspect the `%` change carefully**.

### Gate rule

| Delta | Verdict |
|---|---|
| ≤ +3% | Pass. Ship. |
| > +3% and ≤ +5% *only* on `openssh_brute_force.log` | Flagged worst case. Justify or autoresearch. |
| > +3% on any other Tier 1 file | **Fail.** Invoke autoresearch; do not merge. |

See `.claude/plans/harmonic-churning-karp.md` for the full gate
criteria per implementation phase.

## Configuration knobs

Each bench configures criterion with these settings (defined inline
in each bench file):

```rust
group.sample_size(50);                          // default is 100
group.measurement_time(Duration::from_secs(30));
group.warm_up_time(Duration::from_secs(5));
group.noise_threshold(0.02);                    // 2% = "no change"
group.significance_level(0.01);                 // 1% false-positive rate
```

These values were picked to push the noise floor below the 3% gate
threshold. If you need to iterate faster during development, override
at the CLI level — but note that criterion's group-level settings
**override** CLI flags like `--sample-size`, so you'll need to edit
the bench source for fast-iteration loops.

## Throughput output

Each bench reports throughput in MiB/s via `group.throughput(Bytes(...))`.
This is a more informative number than raw latency for a regression
gate — "the bench is 3% slower" is equivalent to "throughput dropped
3%", and MiB/s is the number you write in a PR body.

## Single-threaded mode is the control

`thread_count == Some(1)` takes an early branch in
`PatternFolder::process_line()` at `src/folder.rs:171`. It avoids
rayon entirely — no thread pool, no batching. This makes it the
deterministic bench control: no cross-thread scheduling noise, no
batch-size artifacts.

The parallel bench (`folder_parallel_e2e`) is a sanity check for the
rayon path, not a throughput claim. Compare it against its own
baseline, not against single-threaded numbers.

## What to look for on a regression

1. **Which bench regressed?** — `folder_e2e` is the gate;
   `folder_streaming_only` and `folder_parallel_e2e` tell you *where*.
2. **Which file regressed?** — a regression on one file and not
   others usually points to a pattern-detector or token-type-specific
   issue.
3. **Does `normalize_line` regress too?** — if yes, the issue is in
   the pattern-detection path, not the folder.
4. **Does `folder_streaming_only` regress?** — if yes, the regression
   is in the per-line hot path, which is unexpected for flush-time
   features. If no, the regression is in flush/finish, which is where
   you'd expect rollup-related changes to show up.
5. **Profile.** Run `cargo bench --bench folder_e2e -- --profile-time
   30` to get per-function samples. Don't guess about where the cost
   lives.

## Running a subset

Criterion accepts a substring filter as a positional argument:

```bash
cargo bench --bench folder_e2e -- nginx_sample          # only the tiny file
cargo bench --bench folder_e2e -- kubelet               # only the kubelet input
cargo bench --bench folder_streaming_only -- postgres   # substring match
```

## Cleaning up baselines

Criterion baselines accumulate under `target/criterion/`. To delete
a specific named baseline:

```bash
find target/criterion -type d -name "main-pre-feature" -exec rm -rf {} +
```

Or nuke all criterion state:

```bash
rm -rf target/criterion/
```
