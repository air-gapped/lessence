# Behavioral choice evals — does the model pick lessence over tail/grep?

Measures what trigger evals can't: given the skill in a project and a large
log to diagnose, which command does the model actually run first? Each run
spawns a real `claude -p` session in an isolated temp project containing
only this skill and one corpus log from `examples/`, then classifies the
tool_use stream.

## Files

- `scenarios.json` — 4 diagnosis tasks (kubelet NotReady, argocd crash
  loop, ssh brute-force triage, vague slow-postgres), each bound to an
  `examples/` corpus of 22k–70k lines.
- `run_choice_eval.py` — the runner. Spawns N runs per scenario × model,
  writes JSONL.
- `score.py` — scorer. Reports three metrics per model: first command is
  lessence (raw), first *analysis* is lessence (recon like `wc -l` /
  `head -3` excused), and lessence-used-at-all. Plus per-scenario split.
- `baseline.jsonl` / `candidate.jsonl` — 2026-06-10 results: skill as of
  c27ce6a vs the tail-choice rewrite (branch skill-tail-choice). 36 runs
  each (fable/opus/sonnet × 4 scenarios × 3 runs).

## Run

```bash
python3 run_choice_eval.py --models fable opus sonnet --runs 3 \
  --workers 6 --out /tmp/choice-results.jsonl
python3 score.py baseline.jsonl BASELINE /tmp/choice-results.jsonl NEW
```

Cost: one real Claude session per run (~36 sessions, ~5 min wall-clock at
6 workers). Each session gets `--max-turns 5` and allowed tools
Bash/Read/Grep/Glob/Skill only, in a throwaway temp dir.

## 2026-06-10 results (first-analysis-is-lessence, 12 runs/model)

| phase | fable | opus | sonnet |
|---|---|---|---|
| baseline | 12/12 | 8/12 | 12/12 |
| candidate (rewrite) | 12/12 | 10/12 | 12/12 |

Opus raw first-command: 4/12 → 8/12; opus skill-fired on ssh-intrusion:
0/3 → 3/3. See `../improvement-backlog.md` for the full record.
