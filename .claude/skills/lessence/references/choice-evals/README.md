# Behavioral choice evals — does the model pick lessence, unprompted?

Measures what trigger evals can't: given a large log to diagnose, which
command does the model actually run first, and does it reach the right
diagnosis? Each run spawns a real `claude -p` session in an isolated temp
project containing one corpus log from `examples/originals/`, then
classifies the tool_use stream and the final answer.

## Two axes

- **primed vs `--cold`** — primed copies `.claude/skills/lessence` into the
  temp project (measures the agent *with* the skill installed). `--cold`
  measures the *unprimed* agent: no skill is copied, and the child process
  gets an isolated `HOME` containing only a copied `.claude/.credentials.json`
  (mode 600) — nothing else. A global `~/.claude/skills/lessence` exists on
  this machine, so a temp cwd alone is not cold; only an isolated `HOME`
  is. Cold runs also pass `--disable-slash-commands`.
- **`--framing none|recon`** — `none` is the bare scenario prompt (what every
  scenario measured before this axis existed). `recon` prepends: "Answer as
  if this is reconnaissance: your job is to make your SECOND command aimed,
  not to finish the investigation in one step." The 2026-08-30 interview
  found framing changes the answer completely — "prints every distinct
  event once with a count" reads as a finished answer and elicits feature
  wishlists, "make your second command aimed" produces a genuinely useful
  first pass. Framing ids and text live in `scenarios.json`'s `framings` map.

## Files

- `scenarios.json` — `framings` (the two framing texts) + `scenarios`: 4
  diagnosis tasks (kubelet NotReady, argocd crash loop, ssh brute-force
  triage, vague slow-postgres), each bound to an `examples/originals/`
  corpus (28k–70k lines) and carrying empty `ground_truth`/`distractors`
  arrays — see below.
- `run_choice_eval.py` — the runner. Spawns N runs per scenario × model,
  writes JSONL. `--dry-run` prints the argv, env delta (redacted values),
  and prompt for every planned run without invoking `claude` or touching
  credentials.
- `score.py` — scorer. Reports first-command-is-lessence (raw),
  first-*analysis*-is-lessence (recon like `wc -l` / `head -3` excused),
  lessence-used-at-all, per-scenario splits, and a behavioral section
  scoring the final answer against `ground_truth`.
- `baseline.jsonl` / `candidate.jsonl` — 2026-06-10 results, **primed axis
  only, framing "none"** (they predate `--cold`, `--framing`, and the
  ground_truth schema; `score.py` fills in the missing fields as defaults
  so they still score). Skill as of c27ce6a vs the tail-choice rewrite
  (branch skill-tail-choice). 36 runs each (fable/opus/sonnet × 4
  scenarios × 3 runs).

## Run

Four combinations:

```bash
# primed, no framing (what baseline.jsonl / candidate.jsonl measured)
python3 run_choice_eval.py --models fable opus sonnet --runs 3 \
  --workers 6 --out /tmp/primed-none.jsonl

# primed, recon framing
python3 run_choice_eval.py --models fable opus sonnet --runs 3 \
  --framing recon --workers 6 --out /tmp/primed-recon.jsonl

# cold (unprimed), no framing
python3 run_choice_eval.py --models fable opus sonnet --runs 3 \
  --cold --workers 6 --out /tmp/cold-none.jsonl

# cold (unprimed), recon framing
python3 run_choice_eval.py --models fable opus sonnet --runs 3 \
  --cold --framing recon --workers 6 --out /tmp/cold-recon.jsonl

python3 score.py /tmp/primed-none.jsonl PRIMED /tmp/cold-none.jsonl COLD
```

Cost: one real Claude session per run (~36 sessions per combination, ~5 min
wall-clock at 6 workers). Each session gets `--max-turns 5` and allowed
tools Bash/Read/Grep/Glob/Skill only, in a throwaway temp dir.

## Coldness verification

A cold run is only evidence about unprimed behaviour if the model was never
told about lessence. After each cold run the runner scans the *entire*
stream-json transcript — every assistant text block and every tool_use
input, not just the commands it classifies — case-insensitively for the
string `lessence`. If it appears anywhere, the record gets
`"cold_violation": true` and a warning is printed to stderr naming the run.
This can happen even with no skill copied and an isolated `HOME`: the model
may still know the tool from training data, or a stray reference could leak
through an unexpected path. `score.py` reports violated runs separately
(excluded from the behavioral score, count shown) rather than folding them
silently into the aggregate.

## Ground-truth schema

Stated preference ("I'd use X") is weak evidence; reaching the right
diagnosis is strong evidence. Each scenario carries:

```json
"ground_truth": [
  {"id": "short-slug", "weight": 1, "any_of": ["case-insensitive regex", "..."]}
],
"distractors": [
  {"id": "short-slug", "any_of": ["case-insensitive regex"]}
]
```

The runner captures the model's **final assistant text message** as
`final_text` on each record, plus `steps` (tool_use count before that
message). `score.py`'s behavioral section matches each `ground_truth` entry's
regexes against `final_text`; a scenario's weighted fraction reached is the
sum of matched weights over the total weight. `distractors` are wrong
conclusions — matched separately, never netted against the score. To add a
scenario: give it `fixture`/`dest`/`prompt` plus these two arrays; all four
scenarios currently ship with **empty** `ground_truth`/`distractors` (the
answers are being derived separately from the corpora) — `score.py` prints
"ground truth not yet derived" and skips scoring rather than reporting a
vacuous 0/0 or 100%.

## 2026-06-10 results (primed axis, framing "none", first-analysis-is-lessence, 12 runs/model)

| phase | fable | opus | sonnet |
|---|---|---|---|
| baseline | 12/12 | 8/12 | 12/12 |
| candidate (rewrite) | 12/12 | 10/12 | 12/12 |

Opus raw first-command: 4/12 → 8/12; opus skill-fired on ssh-intrusion:
0/3 → 3/3. See `../improvement-backlog.md` for the full record. These
numbers say nothing about the cold or framing axes — no cold or
`--framing recon` run has been recorded yet.


## Why the corpora are the originals, not the distilled copies

Every gate in this repo runs on `examples/distilled/`, and this instrument is
the one deliberate exception. The distilled copies are *miniatures*: they hold
every shape of the original but scale its repetition down, so kubelet is 3,951
lines and harbor_postgres is 121. The premise under test here is an agent
facing a log it cannot read in full — at 121 lines it simply reads the file,
and the measurement evaporates. The scenario prompts state the real sizes
(70k / 28k / 39k / 54k lines), which are the originals'.

Do not repoint these at `examples/distilled/`. The corpora are gitignored, so
a fresh clone has neither; the harness fails loudly on a missing fixture rather
than scoring against a file that is not there.


## `--max-turns` is part of the measurement, not a detail

The default is 5, which is what the first-command axis needs: the model's
opening move happens in turn one, and a low cap keeps a sweep cheap.

It is the wrong setting for the behavioural axis. Measured cold on
2026-08-30 at `--max-turns 5`, three of four scenarios ended with
`final_text` reading like *"Let me instead look for genuine process-restart
signatures"* — a mid-investigation sentence, not a diagnosis. Scoring that
against `ground_truth` measures where the cap fell, not what the model knew.
Use `--max-turns 15` or more whenever `ground_truth` is being scored, and
record the value alongside the result.


## First measurement on both axes — 2026-08-30

sonnet, one run per scenario per arm, `--max-turns 25`, framing `none`,
against lessence 0.4.5 (the build then on PATH — this predates the briefing,
so it is the *before* baseline). Every run finished on a verdict: none hit the
turn cap, none was a cold violation.

Tool choice — what the skill changes:

| arm | first command is lessence | first analysis is lessence | ever used |
|---|---|---|---|
| cold (no skill, isolated HOME) | 0/4 | 0/4 | 0/4 |
| primed (skill in the project)  | 2/4 | 3/4 | 4/4 |

Cold, every model opened with the same move — `wc -l`, then `head`, then
`tail`. That habit is the thing the skill has to displace, and now it is
measured rather than assumed.

Diagnosis quality — weighted ground truth reached:

| scenario | cold | primed |
|---|---|---|
| kubelet-notready | 67% (13 steps) | 17% (23 steps) |
| ssh-intrusion | 20% (6 steps) | 80% (9 steps) |
| db-vague | 0% (5 steps) | 40% (6 steps) |
| argocd-crashloop | 20% (10 steps) | 20% (9 steps) |

Two things in that table are worth more than the averages.

**kubelet inverts.** The primed run used lessence, spent 23 steps, and reached
17%; the cold run spent 13 and reached 67%. One run per cell, so this is a
signal to chase and not a conclusion — but it is the flagship corpus and the
tool is supposed to help most there. Re-run it with more repetitions before
believing either number.

**Nobody finds the cause of the kubelet outage.** `apiserver-unreachable`,
the weight-2 finding that IS the answer, is missed 0/8 across both arms.
Every run names the symptoms — lease failures, kubelet restarts, the cilium
socket — and stops there. That is a product target, not a scoring artifact.

The raw run records are deliberately not committed. They contain the models'
verbatim prose about `examples/originals/`, which is raw harvested material,
not the scrubbed distillate — the corpora differ (the original kubelet log
talks to `127.0.0.1:6443`, the distilled copy to an invented address), so the
transcripts carry values that have not been through invention. Publishing
them is the owner's call, not the harness's. Keep result files outside the
tree, or scrub them first.


## Second measurement — 2026-08-30, against the briefing build

Same harness, primed arm only, sonnet, **3 runs per scenario**, `--max-turns
25`, against 0.4.5 f95fda3b5 (the build carrying the briefing). No run
truncated or errored.

| scenario | primed, pre-briefing (n=1) | primed, with briefing (n=3) |
|---|---|---|
| kubelet-notready | 17% | 72% |
| ssh-intrusion | 80% | 53% |
| db-vague | 40% | 20% |
| argocd-crashloop | 20% | 47% |

The single number worth trusting here is the one that is not a percentage of a
small sample: `apiserver-unreachable`, the weight-2 finding that IS the answer
to the kubelet scenario, went from **0/8 across both pre-briefing arms to 3/3**.
That is the result. The scenario percentages move in both directions on n=1
versus n=3 and should not be read as trends — ssh and db-vague going down is
almost certainly sampling, not regression, but nobody has the runs to say so.

Two caveats that belong with any citation of this:

**It is confounded.** The commit that added the briefing also added the
SKILL.md section teaching an agent how to read it. This measures binary and
skill together. To attribute the gain to the output itself, run a primed arm
with the old skill text against the new binary.

**The arms are not matched** — 12 runs after, 8 before, and 1 run per scenario
before against 3 after.

What did not move: the `crashloopbackoff-app-pods` distractor still fires 3/3
on kubelet, so agents name the loudest downstream symptom alongside the cause
rather than instead of it.
