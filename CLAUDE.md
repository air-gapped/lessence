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
make ci             # fmt + clippy + doc + test + deny  (~18 s warm, every commit). Tests run on
                    # the test profile: the release profile (fat LTO, one codegen unit) is
                    # for the shipped binary, and GitHub CI is where it is checked to compile
make gate           # FAILS on exactly five things: a new ##CASE that also passes on the
                    # HEAD build (vacuous), kubelet instructions over +1%, --explain vs
                    # --format json disagreeing on a corpus where the HEAD build agreed,
                    # peak RSS over +32 MiB (default run and --overview all), and default
                    # stdout/stderr bytes or tokens over the reviewed size baseline in
                    # tests/fixtures + max(128, 1%). The golden
                    # diff it prints is material for you to READ, not a verdict — a changed
                    # golden never fails the gate. ≤15 lines, target/gate/gate.json (seconds)
make distill        # examples/distilled/<name>.log + .golden from each examples/originals/<name>.log
                    # via the hidden dev flags `--distill --anonymize` (docs/distill.md):
                    # every shape, no repetition, values invented. BLESS=1 re-blesses golden
make release-check  # the gate against the last PUBLISHED release's build (what users
                    # run; RELEASE_BASE=vX.Y.Z overrides) + mutants on the diff since it
                    # + make ci + the slow (wall-clock) test profile + the README
                    # compression table's freshness. Writes target/gate/release.json (~20 min)
cargo test --lib    # unit tests while iterating
cargo test --test integration known_open_defects -- --ignored --nocapture   # ##TODO status
cargo test --release --test integration invisible_anchor_splits -- --ignored --nocapture  # open anchor classes
make install        # to ~/.cargo/bin, keeping a copy of every build installed under
                    # ~/.local/share/lessence/installed (version + commit) — that archive
                    # is how a new ##CASE is checked against the build that shipped
```

Run `make gate` before committing anything under `src/`; the pre-commit hook
checks that `gate.json` was produced for exactly the staged change. Run
`make release-check` before a release. Nothing else is required per change.

The only perf evidence for a release is the measurement against the last
published release, produced by `make release-check` at handoff and stated
in the handoff as the cumulative number. The per-commit gate compares each
change to its parent and forgets it; a `gate.json` found anywhere else, in a
worktree or from an earlier day, is scratch, not evidence.

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
  runs on: every shape of the originals, their repetition scaled down rather
  than removed (`CONTEXT.md`, "Vocabulary": distilled is fidelity, miniature is
  proportion — that file is the definition, this is a pointer). The
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
| output changed on purpose | `gate.json` → `golden[]`: templates added / removed / recounted, per corpus. **Read the diff — the gate does not judge it.** A re-bless makes any output "correct", so `golden: 0 changed` straight after `BLESS=1 make distill` proves only that you just wrote those files |
| not slower | `gate.json` → `perf.delta_pct`: `instructions:u` on distilled kubelet, single thread, one pinned P-core; threshold +1% |
| a new test can fail | `gate.json` → `cases.new_failing_on_base` |
| memory did not grow | `gate.json` → `rss_kb`: peak RSS of the default run and `--overview all` vs the baseline's default, allowance +32 MiB |
| the default output did not bloat | `gate.json` → `size`: stdout/stderr bytes and tiktoken `cl100k_base` tokens per corpus vs `tests/fixtures/overview-size-baseline.json` + max(128, 1%). Same caveat as the goldens — `GATE_BLESS_SIZE=1` makes any size "correct" |
| mutation score | `mutants.out/outcomes.json` from `make release-check` |

Not evidence: synthetic inputs, wall-clock numbers, a baseline binary you
supplied yourself, a number quoted from memory.
<!-- scar 349493a: a 1M-line synthetic benchmark showed +15%; the real journal went 20 s -> 6 min (0.4.4) -->
<!-- scar: a musl release binary compared against a local glibc build; the allocator was the "win" -->
<!-- scar 2026-08-30: four claims asserted from memory, all wrong — the corpus
     inventory, two root causes read off a commit message rather than measured,
     and a render edge case defended in argument that occurs in 0 of 120
     identities. Each took under a minute to check. Run the command. -->

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

## Orientation

`CONTEXT.md` — vocabulary (distilled vs miniature), what each gate proves and
what it does not, the corpus inventory git cannot show because `examples/` is
gitignored, and the anchor invariant with its open classes. Read it before
claiming what a corpus holds or why a fold split.

## Skills

`.claude/skills/`: **testing** (test commands, ReDoS patterns),
**pattern-dev** (detector order, adding a pattern, normalization internals),
**release** (versioning, changelog, publishing), **lessence** (how an agent
uses the tool — keep it in sync with every user-facing change).
