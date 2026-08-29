# CLAUDE.md - lessence

lessence ("log essence") folds a massive log to its distinct events with
counts, keeping every unique line. It is built for an agent that must
understand a log it cannot read in full: `--explain` is the primary interface,
the text output is a rendering of it. Zero data loss; an over-fold (two events
shown as one) is the worst failure; shape recognisers, never vocabularies.

```bash
lessence app.log                       # file or stdin
kubectl logs pod | lessence
lessence --explain app.log             # JSON: groups, facts, why lines split
lessence --diff <old-binary> app.log   # what an older build folds differently
```

## Commands

```bash
make ci             # fmt + clippy + doc + build + test + deny  (~1 min, every commit)
make gate           # every distilled corpus against its golden inventory; new ##CASE
                    # blocks must fail on the HEAD build; instruction count on distilled
                    # kubelet vs HEAD. ≤15 lines, target/gate/gate.json (seconds)
make distill        # examples/distilled/<name>.log + .golden from each examples/originals/<name>.log
                    # via the hidden dev flags `--distill --anonymize` (docs/distill.md):
                    # every shape, no repetition, values invented. BLESS=1 re-blesses golden
make release-check  # the gate against the last tag's build + mutants on the diff
                    # since the tag + make ci + the slow (wall-clock) test profile. Writes
                    # target/gate/release.json (~20 min)
cargo test --lib    # unit tests while iterating
cargo test --test integration known_open_defects -- --ignored --nocapture   # ##TODO status
```

Run `make gate` before committing anything under `src/`; the pre-commit hook
checks that `gate.json` was produced for exactly the staged change. Run
`make release-check` before a release. Nothing else is required per change.

## Architecture

Pipeline: read → normalize (detectors replace variable parts with placeholders)
→ cluster by token similarity → living template with `<VARIES>` and a counted
rollup → render. `src/normalize.rs` holds the detector order and the anchors
(matched, never scored); `src/patterns/` the detectors, `timestamp/` one
scored table of formats; `src/folder/` clustering and rendering; `src/diff.rs`
the `--diff` mode. Details live in `docs/` and the `pattern-dev` skill.

## The truth layer

These define correct behaviour. Add to them; never weaken them.

- `tests/fixtures/fold_regressions.log` — `##CASE` blocks driven through the
  real binary. Every defect a corpus study finds becomes a `##CASE` with
  invented lines (never copied from a corpus). A new `##CASE` must fail on the
  baseline binary — `make gate` checks — unless its header says
  `holds-on-base`, which declares it a guard of existing behaviour.
  <!-- scar lessence-yuq: five tests that could not fail, one asserting second_run <= first_run*3 -->
- `tests/integration/test_constitutional_compliance.rs` — owned-shape gates:
  each tolerated near-miss names its bead; the tables only shrink.
  <!-- scar: kubelet cap 700 -> 1000 proposed instead of a fix; caps replaced by owned shapes -->
- `examples/distilled/*.log` (gitignored, scrubbed) — the corpora every gate
  runs on: every shape of the originals, none of the repetition. The
  originals in `examples/originals/` are raw material only — studied once,
  distilled by `make distill`, never read by a gate. A gate fails loudly when
  a distilled corpus is missing; no test passes by absence.

The commit-msg hook refuses a commit that removes or edits an existing
`##CASE` header, demotes a `##CASE` to `##TODO`, or grows a `known` table,
unless the message carries `Truth-Layer-Change: <bead> <reason>`.

## Evidence

A claim about behaviour or speed points at a file a script wrote, or it is
not a claim.

| Claim | Evidence |
|---|---|
| tests pass | `make ci` exit 0 in this session |
| output unchanged, or changed on purpose | `gate.json` → `golden[]`: templates added / removed / recounted, per distilled corpus |
| not slower | `gate.json` → `perf.delta_pct`: `instructions:u` on distilled kubelet, single thread, one pinned P-core; threshold +1% |
| a new test can fail | `gate.json` → `cases.new_failing_on_base` |
| mutation score | `mutants.out/outcomes.json` from `make release-check` |

Not evidence: synthetic inputs, wall-clock numbers, a baseline binary you
supplied yourself, a number quoted from memory.
<!-- scar 349493a: a 1M-line synthetic benchmark showed +15%; the real journal went 20 s -> 6 min (0.4.4) -->
<!-- scar: a musl release binary compared against a local glibc build; the allocator was the "win" -->

Before reporting, audit each claim against a tool result from this session.
Report in four parts: **DONE** (what changed, in user terms), **PROOF**
(gate.json numbers, commit hashes), **SCOPE** (what was not touched),
**NOT VERIFIED** (anything without a tool result — say so plainly).

## Commits

Conventional commits drive release notes via release-please. `feat:` / `fix:`
/ `perf:` are user-facing and appear in the changelog — write the first line
for users ("default cap of 30 patterns in --summary mode", not "add
DEFAULT_SUMMARY_CAP"). `test:` / `refactor:` / `style:` / `chore:` / `docs:` /
`ci:` / `build:` are hidden. `RELEASE_COMMIT=1` for `feat:`/`fix:`/`perf:`.
Commit before risky operations. Before `git add`, check `git check-ignore`.

## Safety

- Never run destructive git commands without asking; never push (pushing
  main triggers the release train — the owner pushes).
- Never create planning or scratch files inside the project tree.
- Corpora are scrubbed by invention before they land in `examples/`; nothing
  unscrubbed is ever on disk in the tree.

## Skills

`.claude/skills/`: **testing** (test commands, ReDoS patterns),
**pattern-dev** (detector order, adding a pattern, normalization internals),
**release** (versioning, changelog, publishing), **lessence** (how an agent
uses the tool — keep it in sync with every user-facing change).
