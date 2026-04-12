# `--format json` output schema

Lessence's JSON output mode (selectable via `--format json` or
`--format jsonl`) emits a stream of one JSON object per line
([JSONL](https://jsonlines.org/)), followed by a single terminating
summary record. This is the canonical format for programmatic
consumption — agents, automation, CI pipelines — and is the reason
the structured-folding-output feature exists.

## Why JSONL

- **Streaming-friendly.** Consumers can parse records as they arrive
  and stop early when their context budget is exhausted. Truncating
  JSONL at any line boundary leaves a valid partial result.
- **Pipe-native.** Composes cleanly with `jq`, `grep`, `head`, `awk`.
- **Unambiguous.** Each record is a self-contained object. No need
  to track nesting state across lines.

## Record types

Two record types, discriminated by the `type` field:

1. **`"group"`** — one per flushed PatternGroup, in the same order the
   text-mode output would emit them.
2. **`"summary"`** — exactly one, at the end of the stream, carrying
   the aggregate statistics (input lines, compression ratio, timing,
   per-pattern hit counts).

## Group record

```json
{
  "type": "group",
  "id": 3,
  "count": 1273,
  "token_types": [
    "HASH",
    "IPV4",
    "NAME",
    "PATH",
    "QUOTED_STRING",
    "TIMESTAMP",
    "UUID"
  ],
  "normalized": "E<TIMESTAMP> nestedpendingoperations.go:<NUMBER>] Operation for volume <UUID> failed, err: <QUOTED_STRING>",
  "first": {
    "line": "E0909 13:07:09 ...",
    "line_no": 412
  },
  "last": {
    "line": "E0909 13:45:17 ...",
    "line_no": 9874
  },
  "time_range": {
    "first_seen": "E0909 13:07:09",
    "last_seen": "E0909 13:45:17"
  },
  "variation": {
    "HASH": {
      "distinct_count": 64,
      "samples": ["a1b2c3d", "e4f5g6h", "i7j8k9l", "m0n1o2p", "q3r4s5t", "u6v7w8x", "y9z0a1b"],
      "capped": true
    },
    "IPV4": {
      "distinct_count": 14,
      "samples": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"],
      "capped": false
    },
    "PATH": {
      "distinct_count": 3,
      "samples": ["/var/lib/pods/pod-a", "/var/lib/pods/pod-b", "/var/lib/pods/pod-c"],
      "capped": false
    },
    "TIMESTAMP": {
      "distinct_count": 1273,
      "samples": [],
      "capped": true
    }
  }
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `type` | string | Always `"group"` for group records. |
| `id` | integer | Monotonic counter within a run. Stable: 0 for the first group flushed, 1 for the second, and so on. Resets per invocation. |
| `count` | integer | Number of input lines that joined this group. For a group of 1, this is 1 (no folding). |
| `token_types` | array of strings | Sorted list of token type discriminant names that appeared in the group's first or last line. UPPERCASE convention. Deterministic across runs. |
| `normalized` | string | The first line's normalized form (variable parts replaced with `<TOKEN>` placeholders). This is the "template" that agents group lines by. |
| `first.line` | string | The first input line that created this group, as-is. PII-masked if `--sanitize-pii` is set. |
| `first.line_no` | integer | 1-indexed input line number. In single-threaded mode this is exact; in parallel mode it is approximate (batch-granular — the last line number of the batch the line belonged to). |
| `last.line` | string | The most recent line added to this group (before it flushed). Same semantics as `first.line`. |
| `last.line_no` | integer | Same semantics as `first.line_no`. |
| `time_range.first_seen` | string \| null | Raw string of the first `Token::Timestamp` in the group's first line, or null if no timestamp was detected. Not parsed. |
| `time_range.last_seen` | string \| null | Same, for the group's last line. |
| `variation` | object | Per-token-type rollup metadata. See below. |

### `variation` sub-schema

Each key is a token type name (UPPERCASE, matching `token_types`).
Types are sorted alphabetically (BTreeMap iteration order) for
deterministic diffs across runs.

Each value has three fields:

| Field | Type | Description |
|---|---|---|
| `distinct_count` | integer | Number of distinct values seen for this token type across the group's lines. When `capped: true`, this is a lower bound (`≥ ROLLUP_DISTINCT_CAP`). |
| `samples` | array of strings | Up to `ROLLUP_K` sample values, sorted lexicographically. Empty for count-only token types (TIMESTAMP, NUMBER, DURATION, SIZE, PORT, PID, ...) — those report distinct_count only. |
| `capped` | boolean | `true` if the `ROLLUP_DISTINCT_CAP` was hit during accumulation and further distinct values were dropped. `false` means `distinct_count` is exact. |

### Sample-worthy vs count-only token types

**Sample-worthy** (identity types — samples are useful): `UUID`,
`IPV4`, `IPV6`, `PATH`, `EMAIL`, `HASH`, `K8S_NAMESPACE`, `K8S_VOLUME`,
`K8S_PLUGIN`, `K8S_POD`, `QUOTED_STRING`, `NAME`, `HTTP_STATUS`,
`HTTP_STATUS_CLASS`, `BRACKET_CONTEXT`, `JSON`.

**Count-only** (measurement types — samples would be noise):
`TIMESTAMP`, `PORT`, `PID`, `THREAD_ID`, `DURATION`, `SIZE`, `NUMBER`,
`KEY_VALUE`, `LOG_WITH_MODULE`, `STRUCTURED_MESSAGE`.

The classification is calibrated against real logs; see
`docs/rollup-calibration.md` for the rationale and evidence.

## Summary record

Exactly one, at the end of the stream.

```json
{
  "type": "summary",
  "input_lines": 73421,
  "output_lines": 2841,
  "compression_ratio": 96.13,
  "collapsed_groups": 312,
  "lines_saved": 70580,
  "patterns_detected": 73421,
  "elapsed_ms": 847,
  "pattern_hits": {
    "timestamps": 73421,
    "ips": 12043,
    "hashes": 8734,
    "uuids": 2891,
    "pids": 421,
    "durations": 1832,
    "http_status": 0,
    "sizes": 15,
    "percentages": 3401,
    "paths": 23811,
    "kubernetes": 312,
    "emails": 0
  }
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `type` | string | Always `"summary"`. |
| `input_lines` | integer | Total lines read from the input(s). |
| `output_lines` | integer | Total lines in the formatted output (sum of lines per flushed group record — one line per group in JSON mode). |
| `compression_ratio` | number | `(lines_saved / input_lines) * 100`. Zero if no compression. |
| `collapsed_groups` | integer | Number of groups with `count >= min_collapse`. |
| `lines_saved` | integer | Total lines that were folded away (input - output equivalent). |
| `patterns_detected` | integer | Total number of lines where at least one pattern token was detected. |
| `elapsed_ms` | integer | Wall-clock milliseconds from start of processing. **This is the only intentionally non-deterministic field.** Diff tools should exclude it when comparing runs. |
| `pattern_hits` | object | Per-category token-hit counts. Keys are lowercase category names matching the legacy `--stats-json` output for backwards compatibility. |

## Determinism

**The output is byte-identical across runs** on the same input, with
one exception: `summary.elapsed_ms`. All other fields are reproducible:

- Group `id` is a monotonic counter, stable within a run.
- `token_types` is sorted.
- `variation` keys are sorted (BTreeMap).
- `samples` are drawn via a seeded RNG (`ChaCha8Rng` is stable across
  Linux/macOS/Windows), where the seed is derived from the group's
  normalized template via FNV-1a. Same template → same seed → same
  draw. Drawn samples are additionally sorted lexicographically to
  neutralise HashSet iteration order.
- `first_seen` / `last_seen` are raw strings from the input. Trusted
  as input order, not parsed — so concurrent multi-source logs where
  input order ≠ chronological order will show that in the field.

To verify determinism:

```bash
lessence --format json my.log > /tmp/run1.jsonl
lessence --format json my.log > /tmp/run2.jsonl
diff <(jq -c 'del(.elapsed_ms)' /tmp/run1.jsonl) \
     <(jq -c 'del(.elapsed_ms)' /tmp/run2.jsonl)
```

Expected output: empty.

## Using this from an agent

The design case for this feature is AI agents that pipe large logs
through lessence to produce a triage-ready summary. Typical queries:

### "Which pods had this error?"

```bash
lessence --format json kubelet.log \
  | jq -r 'select(.type == "group" and .count >= 100)
           | .variation.K8S_POD.samples[]?'
```

### "When did this start?"

```bash
lessence --format json app.log \
  | jq -r 'select(.type == "group" and .count > 50)
           | "\(.normalized): \(.time_range.first_seen)"' \
  | head -20
```

### "How many distinct UUIDs are we seeing?"

```bash
lessence --format json pipeline.log \
  | jq '[.type == "group"
         | select(.)
         | .variation.UUID.distinct_count // 0]
        | add'
```

### "Which patterns hit the cap?"

A capped entry means "≥ ROLLUP_DISTINCT_CAP and possibly much more."
These are the high-cardinality patterns worth investigating:

```bash
lessence --format json prod.log \
  | jq -r 'select(.type == "group")
           | .variation
           | to_entries[]
           | select(.value.capped == true)
           | "\(.key): ≥\(.value.distinct_count)"'
```

## Known limitations

- **`line_no` in parallel mode is approximate.** Accurate line
  numbering requires threading per-line indices through the rayon
  batch path, which the Phase 2 design deferred. Use `--threads 1`
  if exact line numbers matter.
- **`time_range` is not chronologically ordered.** It's based on
  first-line/last-line input positions, not parsed timestamp
  comparison. For most logs this matches chronology; for merged
  multi-source logs it may not.
- **Counts can be off by ≤ cap on the 1% tail.** Groups that hit
  `ROLLUP_DISTINCT_CAP` report `distinct_count` as a lower bound with
  `capped: true`. Consumers should treat these as "many".
- **`pattern_hits` keys in the summary are legacy lowercase** to
  match the pre-feature `--stats-json` output. The `variation` map
  inside group records uses UPPERCASE conventions. The two are
  independent.

## See also

- `docs/rollup-calibration.md` — methodology and evidence for the
  rollup constants (`ROLLUP_K`, `ROLLUP_DISTINCT_CAP`,
  `ROLLUP_TEXT_SAMPLE_THRESHOLD`).
- `docs/bench.md` — how to run the performance benchmarks.
- `.ideas/structured-folding-output-for-agents.md` — design
  rationale for the feature.
