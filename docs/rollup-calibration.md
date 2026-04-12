# Rollup Parameter Calibration

This document records the measurement-driven calibration of the three
rollup constants in `src/folder.rs`:

- `ROLLUP_K` — max samples surfaced per token type in JSON mode
- `ROLLUP_DISTINCT_CAP` — per-group, per-token-type distinct-value cap
- `ROLLUP_TEXT_SAMPLE_THRESHOLD` — text-mode inline-sample threshold

These were initially shipped as `PLACEHOLDER_*` constants during Phases
3–4 of the structured-folding-output feature (see
`.ideas/structured-folding-output-for-agents.md`) and retired in Phase 5
using the calibration harness at `benches/calibrate_rollup.rs`.

**Reproducing this report**: `cargo bench --bench calibrate_rollup`.
Re-run whenever the corpus changes or pattern detectors are revised.

## Methodology

The harness runs across the Tier 1 + Tier 2 + Tier 3 corpus
(`examples/*.log`), re-normalises each line via `Normalizer`, groups by
exact normalized template, and records the number of distinct values
per token type per group. This is an approximation of the true
PatternFolder clustering (which uses byte-level similarity, not exact
match), but it tracks the real distinct-count distribution closely
enough for calibration purposes.

Gitignored corpus files are skipped gracefully; the harness works on
partial checkouts and reports how many files were processed.

## Corpus coverage

- Files processed: 18 (of 18 Tier 1/2/3 files present)
- Total unique groups observed: ~5,300 across all files

## Per-token-type distinct_count distribution

Percentiles computed across all (group, token_type) observations:

| Token type | Samples | P50 | P90 | P95 | P99 | Max |
|---|---|---|---|---|---|---|
| BRACKET_CONTEXT | 1,135 | 1 | 1 | 1 | 1 | 2 |
| DURATION | 958 | 1 | 2 | 3 | 17 | 135 |
| EMAIL | 26 | 1 | 2 | 2 | 7 | 7 |
| HASH | 8,377 | 1 | 4 | 7 | 97 | 78,854 |
| HTTP_STATUS | 5 | 1 | 1 | 1 | 1 | 1 |
| HTTP_STATUS_CLASS | 10 | 1 | 1 | 1 | 1 | 1 |
| IPV4 | 7,487 | 1 | 4 | 6 | 29 | 554 |
| IPV6 | 31 | 1 | 2 | 2 | 2 | 2 |
| K8S_NAMESPACE | 504 | 1 | 2 | 3 | 22 | 63 |
| K8S_PLUGIN | 2 | 1 | 1 | 1 | 1 | 1 |
| K8S_POD | 73 | 1 | 7 | 9 | 10 | 10 |
| K8S_VOLUME | 10 | 1 | 1 | 1 | 1 | 1 |
| KEY_VALUE | 1,229 | 1 | 4 | 4 | 11 | 54 |
| NAME | 163 | 1 | 8 | 20 | 62 | 176 |
| NUMBER | 11,001 | 1 | 4 | 7 | 68 | 103,229 |
| PATH | 6,111 | 1 | 2 | 3 | 16 | 586 |
| PID | 3,662 | 1 | 1 | 2 | 5 | 23,328 |
| PORT | 274 | 1 | 116 | 121 | 907 | 2,734 |
| QUOTED_STRING | 2,051 | 2 | 7 | 7 | 24 | 650 |
| SIZE | 81 | 1 | 1 | 1 | 3 | 4 |
| TIMESTAMP | 15,830 | 1 | 4 | 11 | 199 | 103,336 |
| UUID | 454 | 1 | 8 | 18 | 86 | 206 |

### Observations

- **Most groups are low-cardinality.** P50 = 1 for virtually every
  token type — for half the (group, token-type) pairs, there's just
  one distinct value. This is the "all lines share this property"
  signal an agent needs.
- **UUID, HASH, NUMBER, TIMESTAMP dominate the tail.** These are the
  "every occurrence is unique" types. HASH's maximum (78,854) comes
  from a single large group with request-ID-style hashes.
- **PORT's P90 of 116 is surprising.** Investigation: PORT tokenisation
  on some logs picks up arbitrary numbers — probably a pre-existing
  pattern-detector false positive, orthogonal to this calibration.
- **K8S_POD caps at 10** because the upstream pattern detector
  deduplicates pod names internally. The real distinct count may be
  higher.

## ROLLUP_DISTINCT_CAP

**Objective**: smallest cap `P` such that ≥99% of (group, token_type)
pairs on sample-worthy types have `distinct_count ≤ P`.

Across all sample-worthy token types on the corpus:
- P95: 7
- P99: 35
- Max: 78,854

Smallest power-of-two ≥ 35 is **64**.

**Decision: `ROLLUP_DISTINCT_CAP = 64`**

This covers 99% of real groups exactly. The remaining 1% hit the cap
and surface with the `capped: true` flag in JSON output — agents read
that as "≥64 and possibly many more", which is sufficient signal for
triage without blowing memory. Per-group peak memory at the cap is
`64 × ~40 bytes × ~6 sample-worthy types ≈ 15 KB`, trivially small.

## ROLLUP_K

**Objective**: smallest K such that ≥95% of groups have their COMPLETE
sample-worthy distinct set captured (so the JSON `samples` field shows
everything, nothing hidden).

P95 across sample-worthy types = 7. Setting K=7 means for 95% of real
groups, the `samples` array contains every distinct value that
appeared. The remaining 5% (mostly UUID-heavy or NAME-heavy groups)
see a uniform sample of size 7 drawn from the distinct set.

Terminal-width ceiling: K=7 keeps the text-mode inline-sample fallback
short enough that 7 comma-separated values fit on a modern terminal
line in the common case.

**Decision: `ROLLUP_K = 7`**

## ROLLUP_TEXT_SAMPLE_THRESHOLD

**Objective**: largest T such that ≥99% of text-mode compact markers
render within 120 characters (a typical terminal width minus margin).

### Measurement: actual marker lengths on kubelet.log

After applying the calibrated cap and K, and adding per-sample
truncation at 50 chars (see below), actual rendered marker lengths
across 291 folded groups in kubelet.log:

```
min:  12    p50: 199    p90: 396    p95: 442    p99: 479    max: 499
```

P99 is 479 chars — well above 120. **This is not fixable by tuning T**
alone: the dominant source of marker length is the sheer number of
token types per group (8-10 varying token types × ~40 chars each =
300-400 chars of type-label overhead) plus individual sample values.
Reducing T from 3 to 2 or 1 would shorten samples but leave the
type-label overhead intact.

### Mitigation: per-sample value truncation

The most impactful change was truncating individual sample values to
**50 characters** with a `…` suffix. Before truncation, P99 was 976
chars and max was 1417. After truncation, P99 is 479 and max is 499.
The truncation preserves the shape of values (`/var/lib/pods/…`,
`https://api.example.com/…`) while bounding their contribution.

### T selection

With samples truncated, the threshold T primarily affects which small
groups get their complete distinct set shown vs. count-only. At T=3,
groups with 1-3 distinct values show the complete set; larger groups
fall through to count-only. This matches the design principle: show
the complete set when you can, don't show truncated fractions.

**Decision: `ROLLUP_TEXT_SAMPLE_THRESHOLD = 3`**

Higher values did not change the P99 rendering length meaningfully
(the type-label overhead dominates). Lower values (1, 2) sacrifice
useful "show the complete set" behaviour on small groups without
shortening the marker enough to matter.

## What this calibration does NOT do

- **It does not make text markers fit in 120 characters on typical
  real logs.** The median is ~200 chars and P99 is ~500. Users on
  narrow terminals see wrapped lines. A tighter calibration would
  need a structural change (show only the top-N most-varied token
  types per marker), which is future work, not a parameter pick.
- **It does not calibrate against an agent eval.** K's rationale is
  "capture the complete distinct set for 95% of groups," which is a
  proxy for agent utility. A real agent-task eval could push K up or
  down by ±2, but the cost is a full evaluation loop and the benefit
  is modest.
- **It does not account for non-sample-worthy token types.** Count-only
  types (TIMESTAMP, NUMBER, DURATION, SIZE, PORT, PID) are capped at
  the same `ROLLUP_DISTINCT_CAP = 64`, but their distinct_count often
  exceeds that dramatically. The cap forces them to report `capped:
  true` and the count becomes a lower bound — this is intentional,
  since the exact distinct count of a log's TIMESTAMPs is usually not
  useful information for an agent.

## When to re-run this

- When adding a new pattern detector (changes which types are
  sample-worthy and their typical distributions).
- When the Tier 1/2/3 corpus gains or loses significant files.
- When users report the cap being hit too often, or markers being too
  long, on their own logs.

The harness is fast (<60s on a full corpus) and the values can be
tightened or loosened without any schema change — only the constants
in `src/folder.rs` need updating. Tests assert relative invariants
(samples ≤ K, capped=true when cap is hit) rather than absolute values.
