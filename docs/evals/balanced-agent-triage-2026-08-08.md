# Balanced agent triage evaluation — 2026-08-08

## Question

Can a bounded mixture of frequent, rare, and severity-looking patterns retain
rare root causes better than frequency-only output without approaching the size
of full lessence output?

This is an evidence artifact only. It does not define or implement a CLI mode.

## Environment

1. lessence `0.4.5`, commit `cb71966`, release build, `--threads 1`.
2. Claude Code `2.1.226`, model alias `sonnet`.
3. Codex CLI `0.147.0`, configured default model.
4. Two independent runs per agent, scenario, and view: 80 diagnoses total.
5. Date: 2026-08-08.

## Corpus

Five deterministic controlled logs represented Kubernetes, build, test,
structured JSON, and unstructured database-failover diagnostics. Each contained
30 routine patterns repeated 31–60 times, eight rare benign patterns repeated
twice, and one known root cause. The first four root causes appeared 25 times;
the unstructured stale-replica cause appeared once.

| scenario | question | scored answer evidence |
|---|---|---|
| Kubernetes | Why did the api pod restart? | `OOMKilled` or `memory cgroup` |
| build | Why did this build fail? | `undefined reference` or `SSL_CTX_new` |
| test | What caused the test run to fail? | `ledger_reconciliation` or `expected 42` |
| structured JSON | Why can the service not start? | `migration` or `account_id` |
| unstructured | Why are writes inconsistent after failover? | `stale replica` or `LSN` |

Every log also contained harmless severity decoys such as “error budget
healthy”, “panic probe passed”, and “fatal warning policy disabled”. This tests
false priority rather than granting severity keywords perfect precision.

## Views

1. Full: `lessence -q --threads 1 LOG`.
2. Top: `lessence -q --threads 1 --top 20 LOG`.
3. Summary: `lessence -q --threads 1 --summary --top 20 LOG`.
4. Balanced candidate: from unbounded JSON groups, take the 10 highest-count
   groups, five lowest-count groups, and up to five groups matching `error`,
   `fatal`, `panic`, `critical`, `oom`, `killed`, `failed`, `undefined
   reference`, or `exception`; deduplicate by group ID.

The agent prompt was identical for every cell:

> You are diagnosing a log from a bounded diagnostic view. Answer the question
> using only the supplied view. State the most likely root cause in one sentence
> and do not invent missing evidence.

Correctness was a mechanical, case-insensitive match against the answer evidence
above, then manually checked. Incorrect bounded-view answers consistently said
the evidence was absent; they did not hallucinate a cause.

## Raw correctness matrix

Each cell is `run 1 / run 2`; `1` means the diagnosis contained known answer
evidence. Every scenario produced the same row for both agents.

| agent | full | top 20 | summary 20 | balanced |
|---|---:|---:|---:|---:|
| Claude Sonnet, each of 5 scenarios | 1 / 1 | 0 / 0 | 0 / 0 | 1 / 1 |
| Codex, each of 5 scenarios | 1 / 1 | 0 / 0 | 0 / 0 | 1 / 1 |

Aggregated across scenarios and repeats:

| agent | full | top 20 | summary 20 | balanced |
|---|---:|---:|---:|---:|
| Claude Sonnet | 10/10 | 0/10 | 0/10 | 10/10 |
| Codex | 10/10 | 0/10 | 0/10 | 10/10 |
| combined | 20/20 | 0/20 | 0/20 | 20/20 |

## Size, latency, and false priority

Mean view sizes were estimated as UTF-8 bytes divided by four. This is a stable
volume proxy, not model-specific tokenization.

| view | mean approximate tokens | root present | mean generation latency |
|---|---:|---:|---:|
| full | 814 | 5/5 | 19.2 ms |
| top 20 | 448 | 0/5 | 18.8 ms |
| summary 20 | 204 | 0/5 | 18.5 ms |
| balanced | 212 | 5/5 | 19.8 ms |

The balanced view was 74% smaller than full output and 4% larger than summary.
Its observed generation cost was about 1.3 ms above summary in this small
single-process harness; this is not a product benchmark.

The keyword heuristic produced 14 severity candidates, 10 of which were benign
decoys: a 71% heuristic false-priority rate. Despite that, neither agent chose a
decoy as the root cause in any balanced-view run (0/20 false diagnoses). This
shows that severity words are useful recall hints but poor standalone ranking
evidence.

Mean end-to-end agent latency did not improve consistently with shorter views:
Claude ranged from 9.3–10.0 seconds by mode and Codex from 4.5–5.5 seconds.
Network/model variance dominates at this scale.

## Findings

1. The failure mode is real by construction: a frequency cutoff can completely
   remove a diagnostically decisive pattern while accurately reporting routine
   dominant behavior.
2. A balanced selection recovered all five rare causes at summary-sized volume
   for two different agents across two runs.
3. Full lessence output also achieved 20/20 and remains the strongest existing
   workflow when its size is acceptable.
4. Severity matching is noisy. It must not be treated as semantic severity or
   used alone; 71% of matched candidates here were harmless.
5. This controlled corpus establishes capability, not real-world prevalence.
   It deliberately stresses the suspected failure, so 0/20 for bounded
   frequency views must not be interpreted as their general production
   accuracy.

## Decision

Do not ship `--triage` from this evidence. The candidate is promising, but the
evaluation does not quantify how often rare-cause displacement occurs in real
logs, and the severity heuristic has high false-positive pressure. Retain the
current behavior and existing full-output-plus-filtering workflow. Any product
experiment requires a separate owner-approved bead using naturally occurring
diagnostic corpora and independently established ground truth.
