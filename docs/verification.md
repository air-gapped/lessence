# Verification: gates, hooks, distilled corpora

Contracts for `make ci`, `make gate`, `make distill`, `make release-check`
and the commit hooks. Rationale is not here; the rules are in CLAUDE.md.

## Tiers

| Target | Run when | Reads | Writes | Exit |
|---|---|---|---|---|
| `make ci` | every commit | tests, `tests/fixtures/` | — | non-zero on any failure |
| `make gate` | before a commit touching the binary's inputs (below) | `examples/distilled/*.log`, `*.golden`, `tests/fixtures/fold_regressions.log` | `target/gate/gate.json` | 0 PASS · 1 FAIL · 2 cannot run |
| `make distill` | after a corpus is added or re-harvested; `BLESS=1` after an intended fold change | `examples/originals/*.log` (originals, this step only) | `examples/distilled/<name>.log`, `<name>.golden` | non-zero names the corpus |
| `make release-check` | before a release | distilled set, `<last-published-release>..HEAD`, the `slow` nextest profile, README compression table, skill `sources.md` | `target/gate/release.json` | as gate |

No target other than `make distill` reads an original corpus.

## `scripts/gate.sh`

1. Preconditions: at least one `examples/distilled/*.log` with a `.golden`
   beside it, else exit 2 listing what is missing. `perf stat -e
   instructions:u` must work unprivileged (`/proc/sys/kernel/perf_event_paranoid`
   ≤ 2), else exit 2.
2. Baseline: `GATE_BASE` (default `HEAD`) checked out into a worktree under
   `target/gate/`, built with the current toolchain into the shared
   `target/gate/base-target`, cached as `target/gate/base-<commit>/lessence`;
   the worktree is removed once the binary is copied out. A cached binary is
   reused without a checkout or a build. A binary path is never accepted.
   If `git diff <base>` over the binary's inputs — `src/`, `Cargo.toml`,
   `Cargo.lock`, `build.rs` and the two skill files `src/skill.rs` embeds
   (`.claude/skills/lessence/SKILL.md`, `references/flags.md`) — is empty
   → exit 2 "nothing to compare".
3. New: `cargo build --release` of the working tree. sha256 of both binaries
   recorded.
4. Cases: `##CASE` headers in the working-tree fixture absent from the
   baseline commit's fixture are new. Each new block is run against the
   baseline binary (`LESSENCE_BIN`, `LESSENCE_FIXTURE` overrides in
   `tests/integration/test_fold_regressions.rs`). A new block that passes on
   the baseline and lacks `holds-on-base` in its header is vacuous → FAIL,
   headers listed. A run is judged only on a result the test reported
   (`scripts/gate-vacuity.sh`): `known_fold_regressions ... ok` with exit 0
   is a pass, `... FAILED` with the case check's "N of M fold regressions
   came back" is a fail; anything else — a compile failure, a filter that
   ran nothing, a panic before the case was checked — is exit 2 naming the
   case, never "fails on the baseline". With `GATE_VACUOUS_INFORMATIONAL=1` (set by
   `release-check.sh`, whose baseline is the last tag) the count is printed
   and listed in `gate.json` but does not fail: against a tag, passing only
   means the tag never had that defect.
5. Golden: for each distilled corpus, the new binary's `--explain` inventory
   (`count<TAB>template` per group, sorted) is compared to `<name>.golden`.
   Changed corpora are printed (templates added / removed / recounted) and
   listed in `gate.json`; a change alone is not a FAIL.
5b. Modes: for each distilled corpus, the `--explain` and `--format json`
   inventories are taken for both binaries and the rows the two modes do not
   share are counted (`comm -3`). The two modes fold the same way, so they
   must agree. A corpus where the baseline count is 0 must stay 0 → FAIL
   otherwise; a corpus already carrying a residual on the baseline
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
   and nothing outside it is touched. The build of the newest tag reachable
   from HEAD (`RELEASE_BASE` overrides; cached like the baseline) is measured
   the same way: FAIL when the working tree is over it by more than
   `GATE_PERF_RELEASE_MAX` (default 2.0), so steps that each pass the
   per-change limit cannot add up unseen. A clone without tags skips this
   and prints that it did.
7. Peak RSS (`/usr/bin/time -v`, `scripts/gate-rss.sh`) on the same corpus
   for the baseline default, the new default and the new `--overview all`.
   FAIL when either new number is more than 32 MiB over the baseline default.
   Fails closed: all three runs must exit 0 and report a numeric peak RSS, and
   an absent `/usr/bin/time` (`GATE_TIME` overrides the path) is a FAIL, never
   a PASS with no measurement. A failed run's stderr is kept as
   `target/gate/rss-<label>.stderr`.
8. Size (`scripts/gate-size.py`): stdout and stderr bytes and pinned-tokenizer
   tokens (tiktoken `cl100k_base`, version recorded) per corpus at default
   flags, against the reviewed baseline
   `tests/fixtures/overview-size-baseline.json`. FAIL when any compared field
   exceeds its baseline + max(128, 1%). Fails closed: no tokenizer, no
   baseline file, a corpus absent from the baseline, a missing baseline field
   or a non-zero exit from the measured run are FAILs naming the cause, never
   skips. The 16 KiB bound is asserted on the run's actual, unmodified stdout
   bytes. Only the *comparative* metric normalises the locator text that says
   nothing about the overview — the report path, the run id and the reported
   byte size become `<REPORT>`, `<RUN>` and `<SIZE>` — so the baseline does
   not depend on the checkout path or the run. Each corpus also records its
   own sha256 and the run's total/selected/printed/omitted/previewed counts,
   and the baseline's sha256 is recorded, so a comparison identifies the
   artifacts it was made against. `GATE_BLESS_SIZE=1` rewrites the baseline —
   a number written by the run that is being judged proves nothing, so
   re-bless deliberately and read the diff; it is never implied by an
   ordinary run, and it refuses to write when the measurement had errors.
   `scripts/gate-selftest.sh` drives both checks with stubs (missing
   tokenizer, missing baseline, missing corpus, missing field, genuine growth,
   over-16-KiB stdout, failed RSS run, RSS report with no number, and the
   vacuity classification of step 4) and runs as a precondition of every
   gate.
9. Stdout ≤ 15 lines. `gate.json`:
9. Mutants on the change (`scripts/mutants.sh ... --in-diff`), only when the
   baseline is HEAD: the lines changed under `src/folder`, `src/normalize.rs`
   and `src/patterns` are mutated and the unit tests run on each. FAIL on a
   missed mutant, naming it, and on a run that did not complete. An
   equivalent mutant gets an `exclude_re` entry in `.cargo/mutants.toml`
   with its proof. `GATE_SKIP_MUTANTS=1` skips the step for testing the
   script; release-check runs its own over the whole release.

```json
{ "time": "", "git_head": "", "staged_diff_sha256": "scripts/gate-diff-hash.sh: sha256(git diff HEAD, .beads/ excluded)",
  "base": {"ref": "HEAD", "commit": "", "sha256": ""},
  "new":  {"sha256": "", "rustc": ""},
  "cases": {"new": 0, "new_failing_on_base": 0, "vacuous": []},
  "golden": [{"corpus": "", "added": [], "removed": [], "recounted": []}],
  "modes": [{"corpus": "", "base": 0, "new": 0}],
  "perf": {"cpu": 0, "instructions_base": 0, "instructions_new": 0,
           "spread_pct": 0.0, "delta_pct": 0.0, "threshold_pct": 1.0},
  "rss_kb": {"base_default": 0, "new_default": 0, "new_overview_all": 0, "allowance_kb": 32768},
  "size": {"tokenizer": {"name": "tiktoken", "encoding": "cl100k_base", "version": ""},
           "baseline": "overview-size-baseline.json", "baseline_sha256": "",
           "stdout_limit_bytes": 16384, "corpora_measured": 0, "corpora_baselined": 0,
           "corpora": {"<name>": {"stdout_bytes": 0, "stderr_bytes": 0, "stdout_tokens": 0,
                        "stderr_tokens": 0, "corpus_sha256": "", "total": 0, "selected": 0,
                        "printed": 0, "omitted": 0, "previewed": 0}},
           "errors": [], "over": []},
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

The base is the last **published** release, found with `gh release list
--exclude-drafts --exclude-pre-releases` (`RELEASE_BASE=vX.Y.Z` overrides;
without `gh` the newest tag is used and a warning says so). Checks, in order:
`scripts/gate.sh` against that base (new-case vacuity is counted, not failed);
`cargo mutants --in-diff` on `<base>..HEAD` via `scripts/mutants.sh`
(`mutants.out/outcomes.json` is the score); the README compression table was
generated at a commit whose `src/` equals HEAD's
(`scripts/readme-compression.sh --check`); every user-facing `src/` commit after the agent skill's `sources.md`
`verified-at:` sha updates the skill in the same commit or carries
`Skill-Unchanged: <reason>`; `make ci`; `cargo nextest run --release --profile slow`. Writes `target/gate/release.json`, prints ≤ 25
lines. `RELEASE_CHECK_SKIP_MUTANTS=1` skips mutants (testing only).

## Checks built into test builds

Three `debug_assert!`s run inside the binary and the library wherever tests
build them (`make ci`, the mutants profile), on every line of every corpus
and `##CASE` the tests fold. A release build compiles them out.

1. **The template holds** (`template_holds`, `src/folder/mod.rs`): each time a
   line joins a group, the group's template reads true of that line and of
   the group's first line both ways. Every unit of the template is on the
   line, in order, and every unit of the line is shown by one unit of the
   template: a plain unit by the one equal to it, a bare `<VARIES>` by any
   run of them or none, a unit with text beside its slot (`msg=<VARIES>`)
   by a run that starts and ends with that text. A line may hold no word
   the template does not show. Read character by character instead, each
   `<VARIES>` standing for any text, when a slot swallowed a quote and the
   two no longer split into the same units.
2. **A prefilter only saves time** (`DETECTOR_ORDER`, `src/normalize.rs`): when
   a detector's `prefilter` turns a line away, the detector is run anyway and
   must change nothing. A rule that keeps a detector off a line it would
   change is the entry's `only_when`, which is not checked.
3. **A gate is no narrower than its pattern** (`gate`, `src/normalize.rs`):
   when the byte test before an anchor pattern turns a line away, the pattern
   must find nothing on it.

`known_fold_regressions` prints the panic when one of these stops a case.

## Test profiles (`.config/nextest.toml`)

The default profile's `default-filter` excludes the tests that assert a
duration (every `*scales_linearly*` test, `test_processing_speed_requirement`
and the others `.config/nextest.toml` names), the 200,000-group
`--overview all` streaming test and the corpus-wide detector-order test. The `slow`
profile is exactly those, run by `make release-check`
and by hand with `cargo nextest run --release --profile slow`. A `-E`
expression on the command line selects within the profile's default filter
unless `--ignore-default-filter` is given, so `make ci` can never run a slow
test by accident and `make release-check` always runs all of them.

## Hooks (`.githooks/`, `core.hooksPath`)

- `pre-commit`: if a staged path (added, changed, deleted, or either side
  of a rename) is one of the binary's inputs (`scripts/gate.sh`, step 2), require
  `target/gate/gate.json` with `verdict: PASS` and `staged_diff_sha256`
  equal to `scripts/gate-diff-hash.sh` now (the working tree against HEAD,
  staged or not, `.beads/` left out); otherwise print `run make gate` and
  exit 1. When that gate run changed any golden, it also requires
  `target/gate/review.json` with `verdict: pass` for the same
  `staged_diff_sha256` (`scripts/check-fold-review.sh`). The fold-reviewer
  agent (`.claude/agents/fold-reviewer.md`) reads the golden diff against
  the corpus lines and writes that file with `scripts/record-review.sh`;
  `.claude/hooks/build-guard.sh` refuses that script from the main session.
- `commit-msg`: diff `##CASE`/`##TODO` headers in
  `tests/fixtures/fold_regressions.log` and entries in the `known` tables of
  `tests/integration/test_constitutional_compliance.rs` between `HEAD` and
  the index. A removed or altered `##CASE` header, a `##CASE` → `##TODO`
  demotion, or more `known` entries requires the trailer
  `Truth-Layer-Change: <bead> <reason>` in the message; otherwise exit 1
  naming the change. A `feat:`/`fix:`/`perf:` commit that stages a change
  under `src/` must also stage one under `.claude/skills/lessence/` or
  carry `Skill-Unchanged: <reason>`; otherwise exit 1.
- `pre-commit` and `commit-msg` both run `scripts/check-public-text.sh`:
  exit 1 on a staged file named like a security working document, on an
  added line of Markdown or of the issue export that describes a weakness,
  on a commit message that does, and on an added line or message holding a
  string from the local, untracked `.private-names` or `.blocklist`, both
  read from the main checkout so a linked worktree uses them too.
- `pre-push`: `scripts/check-public-text.sh --outgoing` runs the same
  checks on every commit the push would send, then `make ci`.

`.claude/settings.json` registers `.claude/hooks/build-guard.sh` as a PreToolUse
hook on Bash: a command that builds or tests is refused while another
cargo, rustc or nextest process runs, or while less than 10 GB of memory is
available (`LESSENCE_BUILD_MIN_AVAILABLE_GB`).

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
