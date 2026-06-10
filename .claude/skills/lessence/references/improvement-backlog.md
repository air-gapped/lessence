# Improvement backlog — lessence skill

Carries findings across skill-improver runs. See skill-improver's SKILL.md
Phase 0/6 for how this file is consumed.

## Open

- **journalctl / test-failure triggers have no matching workflow example**
  (Dim 5) — `when_to_use` promises both, Triage Workflows covers neither.
  Flagged by the final blind scorer (2026-06-09). (carried 2026-06-10)
- **Opus residual: grep-first on half-known-keyword security triage** —
  choice eval 2026-06-10 (ssh-intrusion scenario): after the boundary fix the
  skill now FIRES on opus (3/3, was 0/3) but opus still runs `grep Accepted`
  before lessence in 2/3 runs. Defensible behavior (half the question IS a
  known keyword); not fixable by frontmatter without over-claiming grep
  territory. Revisit only if real-world sessions show it matters.

## Resolved this pass — 2026-06-10 (tail-choice rewrite, branch skill-tail-choice)

- **Choice-eval harness adopted into the repo** (owner-approved 2026-06-10)
  — references/choice-evals/{README.md,scenarios.json,run_choice_eval.py,
  score.py,baseline.jsonl,candidate.jsonl}; runner paths made
  repo-relative.
- **Behavioral choice eval built and run on 3 models** (fable, opus, sonnet;
  4 scenarios × 3 runs/model/phase; real `claude -p` sessions in isolated
  temp projects with a 22k–70k-line corpus log). Baseline → candidate,
  first-analysis-is-lessence: fable 12/12 → 12/12, sonnet 12/12 → 12/12,
  opus 8/12 → 10/12; opus first-command 4/12 → 8/12; opus ever-used 9 → 11.
- **Opening paragraph duplicated frontmatter** (Dim 6, carried from
  2026-06-09) — replaced with the silent-vs-declared-omission principle +
  no-recon-needed note. Closed.
- **"wall of text" trigger flakiness** (carried from 2026-06-09) — added
  "wall of text", "build log", "what's actually failing" to when_to_use.
  Measured: 0.0 → 0.8 (5 runs), 0.67 on re-probe (3 runs); passes at the
  0.5 threshold. Known borderline query; history: 0.50 at 06-09 baseline.
- **Trigger eval set extended 13 → 18 queries** — 3 new should-trigger
  (self-limiting habit vocabulary) + 2 new should-not (tail -f live-follow,
  wc -l trivia). Full-set probe: 17/18 before the wall-of-text fix, all 8
  negatives 0.0 throughout (incl. original "last 20 lines" decoy).
- **Known-keyword negative boundary over-claimed** — "ONLY a known-keyword
  search" + exploratory carve-out added; fixed opus never-triggering on
  security triage (skill fired 0/3 → 3/3 on ssh-intrusion).

## Resolved — 2026-06-09

- Improve loop: 76 → 86 (self), 79 → 86 (blind). 9 kept iterations, 0
  discards (stopped at the 10-iteration cap, not at a mapped ceiling):
  flags.md `--format json` row, sources.md created with probed stamps
  (Dim 9 cap lifted), --top pitfall deduplicated, sources pointer,
  exit-code table, min-collapse floor + binary help-text fix (blind
  baseline findings, verified by execution), negative triggers,
  H1 second-person fix, hash×64+ cap correction.
- Freshen: 11 claims probed against the v0.4.3 binary (local execution),
  all stamped `Last verified: 2026-06-09`; all five jq recipes verified
  end-to-end against examples/kubelet.log.
- Trigger mode: eval set created (13 queries, persisted in
  trigger-evals.json). Baseline train 8/9, test 4/4. One kept mutation
  (pushier crash-loop trigger): train 9/9, test 3/4 (regression within
  the n=2 noise bar). Zero false positives across all probes.
