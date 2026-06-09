# Improvement backlog — lessence skill

Carries findings across skill-improver runs. See skill-improver's SKILL.md
Phase 0/6 for how this file is consumed.

## Open

- **Opening paragraph duplicates the frontmatter description** (Dim 6) —
  SKILL.md:18-22 restates the description nearly verbatim. Flagged by the
  final blind scorer (2026-06-09) after the iteration cap; not attempted.
  Fix: replace with non-redundant content (e.g. one-line pipeline diagram)
  or delete. Single-iteration change.
- **journalctl / test-failure triggers have no matching workflow example**
  (Dim 5) — `when_to_use` promises both, Triage Workflows covers neither.
  Flagged by the final blind scorer (2026-06-09) after the iteration cap.
  Fix: add one journalctl example (or fold into the crash-loop example) OR
  trim the trigger phrases. Single-iteration change either way.
- **Test-split flakiness on "CI build log is a wall of text"** (trigger
  mode) — trigger rate 0.50 at baseline, 0.00 after the kept mutation
  (n=2 runs; below the 2-query overfit bar). Re-probe with
  `--runs-per-query 5` before treating as a real miss; if real, add
  "wall of text" alongside "wall of logs" in `when_to_use`.

## Resolved this pass — 2026-06-09

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
