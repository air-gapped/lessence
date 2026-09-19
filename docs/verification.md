# Verification: gates, hooks, distilled corpora

Contracts for `make ci`, `make gate`, `make distill`, `make release-check`
and the commit hooks. Rationale is not here; the rules are in CLAUDE.md.

## Tiers

| Target | Run when | Reads | Writes | Exit |
|---|---|---|---|---|
| `make ci` | every commit | tests, `tests/fixtures/` | — | non-zero on any failure |
| `make gate` | before a commit touching `src/` or `Cargo.lock` | `examples/distilled/*.log`, `*.golden`, `tests/fixtures/fold_regressions.log` | `target/gate/gate.json` | 0 PASS · 1 FAIL · 2 cannot run |
| `make distill` | after a corpus is added or re-harvested; `BLESS=1` after an intended fold change | `examples/*.log` (originals, this step only) | `examples/distilled/<name>.log`, `<name>.golden` | non-zero names the corpus |
| `make release-check` | before a release | distilled set, `<last-tag>..HEAD`, the `slow` nextest profile | `target/gate/release.json` | as gate |

No target other than `make distill` reads an original corpus.

## `scripts/gate.sh`

1. Preconditions: at least one `examples/distilled/*.log` with a `.golden`
   beside it, else exit 2 listing what is missing. `perf stat -e
   instructions:u` must work unprivileged (`/proc/sys/kernel/perf_event_paranoid`
   ≤ 2), else exit 2.
2. Baseline: `GATE_BASE` (default `HEAD`) checked out into a worktree under
   `target/gate/`, built with the current toolchain, cached as
   `target/gate/base-<commit>/lessence`. A binary path is never accepted.
   If `git diff <base> -- src Cargo.lock` is empty → exit 2 "nothing to compare".
3. New: `cargo build --release` of the working tree. sha256 of both binaries
   recorded.
4. Cases: `##CASE` headers in the working-tree fixture absent from the
   baseline commit's fixture are new. Each new block is run against the
   baseline binary (`LESSENCE_BIN`, `LESSENCE_FIXTURE` overrides in
   `tests/integration/test_fold_regressions.rs`). A new block that passes on
   the baseline and lacks `holds-on-base` in its header is vacuous → FAIL,
   headers listed. With `GATE_VACUOUS_INFORMATIONAL=1` (set by
   `release-check.sh`, whose baseline is the last tag) the count is printed
   and listed in `gate.json` but does not fail: against a tag, passing only
   means the tag never had that defect.
5. Golden: for each distilled corpus, the new binary's `--explain` inventory
   (`count<TAB>template` per group, sorted) is compared to `<name>.golden`.
   Changed corpora are printed (templates added / removed / recounted) and
   listed in `gate.json`; a change alone is not a FAIL.
5b. Modes: for each distilled corpus, the `--explain` and `--format json`
   inventories are taken for both binaries and the rows the two modes do not
   share are counted (`comm -3`). `--explain` never evicts and `--format json`
   does, so the two must agree. A corpus where the baseline count is 0 must
   stay 0 → FAIL otherwise; a corpus already carrying the eviction residual
   (lessence-3ck) is printed, not judged. Corpora with a non-zero count on
   either binary are printed (`modes:` line) and listed in `gate.json`.
6. Perf: `taskset -c $GATE_CPU perf stat -e instructions:u,task-clock -x, --
   <bin> --threads 1 -q examples/distilled/kubelet.log`, base then new, two
   rounds, minimum per binary; a third round if the two differ by > 0.3%.
   `GATE_CPU` = first cpu in `/sys/devices/cpu_core/cpus`. FAIL when
   `delta_pct > GATE_PERF_MAX` (default 1.0). The measured run is the real
   default — report written and overview printed — with `--report-dir` set to
   `target/gate/reports` when the binary supports it, so nothing lands in the
   caller's state directory; that directory is removed after the measurement
   and nothing outside it is touched.
7. Peak RSS (`/usr/bin/time -v`) on the same corpus for the baseline default,
   the new default and the new `--overview all`. FAIL when either new number
   is more than 32 MiB over the baseline default. Skipped, and said so, where
   `/usr/bin/time` is absent.
8. Size: stdout and stderr bytes and pinned-tokenizer tokens (tiktoken
   `cl100k_base`) per corpus at default flags, against the reviewed baseline
   `tests/fixtures/overview-size-baseline.json`. FAIL when any field exceeds
   its baseline + max(128, 1%). The report path is replaced by `<REPORT>`
   before counting, so the baseline does not depend on the checkout path.
   `GATE_BLESS_SIZE=1` rewrites the baseline — a number written by the run
   that is being judged proves nothing, so re-bless deliberately and read the
   diff.
9. Stdout ≤ 15 lines. `gate.json`:

```json
{ "time": "", "git_head": "", "staged_diff_sha256": "sha256(git diff --cached; git diff)",
  "base": {"ref": "HEAD", "commit": "", "sha256": ""},
  "new":  {"sha256": "", "rustc": ""},
  "cases": {"new": 0, "new_failing_on_base": 0, "vacuous": []},
  "golden": [{"corpus": "", "added": [], "removed": [], "recounted": []}],
  "modes": [{"corpus": "", "base": 0, "new": 0}],
  "perf": {"cpu": 0, "instructions_base": 0, "instructions_new": 0,
           "spread_pct": 0.0, "delta_pct": 0.0, "threshold_pct": 1.0},
  "rss_kb": {"base_default": 0, "new_default": 0, "new_overview_all": 0, "allowance_kb": 32768},
  "size": {"tokenizer": "tiktoken cl100k_base", "baseline": "overview-size-baseline.json",
           "corpora_measured": 0, "corpora_baselined": 0, "over": []},
  "verdict": "PASS" }
```

## `scripts/distill.sh`

For each `examples/originals/<name>.log`:

```
target/release/lessence --distill --anonymize --seed 1 \
    --anonymize-words "$SCRUB_VOCAB" examples/originals/<name>.log > examples/distilled/<name>.log
```

The command exits non-zero if a template or word shape was lost or an
original value survived (`docs/distill.md`); the script stops and names the
corpus. Then `--explain` on the distilled file → `<name>.golden`
(`count<TAB>template`, sorted). Without `BLESS=1` an existing `.golden` is
compared, not overwritten; a difference is printed and exits 1. With
`BLESS=1` it is rewritten and the delta printed. Finally
`grep -E "$SCRUB_FORBID"` over the output must match nothing.
`SCRUB_VOCAB` and `SCRUB_FORBID` are the files/regex the harvest used; both
live outside the tree.

## `scripts/release-check.sh`

`GATE_BASE=$(git describe --tags --abbrev=0) scripts/gate.sh`; `cargo mutants
--in-diff <(git diff <tag>..HEAD)` with the flags `make mutants` uses
(`mutants.out/outcomes.json` is the score); `make ci`; `cargo nextest run
--release --profile slow`. Writes `target/gate/release.json`, prints ≤ 25
lines. `RELEASE_CHECK_SKIP_MUTANTS=1` skips mutants (testing only).

## Test profiles (`.config/nextest.toml`)

The default profile's `default-filter` excludes every `*scales_linearly*`
test and `test_processing_speed_requirement` — the tests that assert a
duration. The `slow` profile is exactly those, run by `make release-check`
and by hand with `cargo nextest run --release --profile slow`. A `-E`
expression on the command line selects within the profile's default filter
unless `--ignore-default-filter` is given, so `make ci` can never run a slow
test by accident and `make release-check` always runs all of them.

## Hooks (`.githooks/`, `core.hooksPath`)

- `pre-commit`: if a staged path is under `src/` or is `Cargo.lock`, require
  `target/gate/gate.json` with `verdict: PASS` and `staged_diff_sha256`
  equal to the current staged diff; otherwise print `run make gate` and
  exit 1.
- `commit-msg`: diff `##CASE`/`##TODO` headers in
  `tests/fixtures/fold_regressions.log` and entries in the `known` tables of
  `tests/integration/test_constitutional_compliance.rs` between `HEAD` and
  the index. A removed or altered `##CASE` header, a `##CASE` → `##TODO`
  demotion, or more `known` entries requires the trailer
  `Truth-Layer-Change: <bead> <reason>` in the message; otherwise exit 1
  naming the change.

## Corpus-dependent tests

`tests/common/mod.rs::require_example(path)`: panics naming the path when the
file is missing, unless env `CI` is set (prints a skip line, returns). Used
by every test that reads `examples/distilled/`.

## Distillation acceptance

`lessence --distill` produces a candidate; the candidate is not a corpus
until an agent that has learned the original accepts it. Lessence's own
checks (template set, word shapes) are necessary, not sufficient — the tool
cannot certify its own output.

Per corpus, one Sonnet agent, with the corpus's study report from
`examples/lab-audit/study-*` (ground truth built by shell before lessence
ran) and the original file:

1. Rebuild the ground-truth event list by shell on the original
   (`awk`/`sed`/`sort | uniq -c`, never lessence) — the study's method.
2. For every event family in that list, find it in
   `examples/distilled/<name>.log` (grep on the invented copy, matching on
   structure: the words, not the values). A family that is absent is a
   miss.
3. For every miss, append the earliest original line of that family to the
   distilled file through `lessence --anonymize --seed 1` (same seed, same
   inventions) and record the family in `examples/distilled/<name>.accept`
   as `added: <shape>`; a distillation with misses is also a `--distill`
   defect — file the shape as a `##TODO` on the fixture.
4. Re-run every `##CASE` that names this corpus's bead against the
   distilled copy.
5. Write `<name>.accept`: `accepted-by`, `study`, `families`, `found`,
   `added`, `cases`. `make distill` refuses to write a `.golden` for a
   corpus without an `.accept` unless `BLESS=1`, and prints which are
   missing.

A corpus without a study report gets one first (the corpus-study method).
The accept files are the record that the learning, not the tool, is the
oracle.

## Evidence rules

Evidence is a file one of these scripts wrote, or a test run in this
session. Not evidence: synthetic input, wall-clock numbers, a baseline binary
supplied by hand, a number from memory.
