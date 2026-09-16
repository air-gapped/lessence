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
    "source": "kubelet.log",
    "line": "E0909 13:07:09 ...",
    "line_no": 412
  },
  "last": {
    "source": "kubelet.log",
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
| `normalized` | string | The first line's normalized form (variable parts replaced with `<TOKEN>` placeholders). This is the "template" that agents group lines by. PII-masked if `--sanitize-pii` is set. |
| `first.source` | string \| null | Explicit input filename exactly as supplied to lessence, or null for stdin. |
| `first.line` | string | The first input line that created this group, as-is. PII-masked if `--sanitize-pii` is set. |
| `first.line_no` | integer | Exact 1-indexed line number within `first.source`, or within stdin when `source` is null. |
| `last.source` | string \| null | Source of the group's last representative, with the same semantics as `first.source`. A group can span input files. |
| `last.line` | string | The most recent line added to this group (before it flushed). Same semantics as `first.line`. |
| `last.line_no` | integer | Exact 1-indexed line number within `last.source`, or within stdin when `source` is null. |
| `time_range.first_seen` | string \| null | Raw string of the first `Token::Timestamp` in the group's first line, or null if no timestamp was detected. Not parsed. |
| `time_range.last_seen` | string \| null | Same, for the group's last line. |
| `variation` | object | Per-token-type rollup metadata. See below. |

### `variation` sub-schema

CPU resource fields expressed in millicpu use `CPU_QUANTITY` in
`token_types` and `variation`. Their exact textual values (for example
`750m`) are sample-worthy; existing sample caps and completeness fields apply.
The summary's `pattern_hits.cpu_quantities` and briefing token class
`cpu_quantities` count these values separately from durations.

Each key is a token type name (UPPERCASE, matching `token_types`).
Types are sorted alphabetically (BTreeMap iteration order) for
deterministic diffs across runs.

Each value records both the bounded data and how to interpret its counts:

| Field | Type | Description |
|---|---|---|
| `distinct_count` | integer | Number of distinct values seen for this token type across the group's lines. When `capped: true`, this is a lower bound (`≥ ROLLUP_DISTINCT_CAP`). |
| `distinct_count_kind` | `"exact"` \| `"lower_bound"` | Explicit interpretation of `distinct_count`. |
| `samples` | array of strings | Up to `ROLLUP_K` sample values, sorted lexicographically (`VARIES`: by count, most frequent first, rarest last). Empty for count-only token types (TIMESTAMP, NUMBER, DURATION, SIZE, PORT, PID, ...) — those report distinct_count only. With `--sanitize-pii`, EMAIL samples collapse to `<EMAIL>`, email values embedded in other types' samples are masked as well, and credential-class values in samples are masked (`<SECRET>`/`<JWT>`/`<KEY>`). |
| `capped` | boolean | `true` if the `ROLLUP_DISTINCT_CAP` was hit during accumulation. `distinct_count` is then a lower bound. This also covers retained unequal-length shapes; see below. `false` means `distinct_count` is exact. |
| `sample_counts` | array of integers | `VARIES` only: how many of the group's lines carried each entry of `samples`, same order. Absent on every other type. |
| `samples_complete` | boolean | Whether `samples` contains the complete distinct set. |
| `omitted_sample_values` | count object | Distinct values not included in `samples`; lower-bound when capped. |

### Sample-worthy vs count-only token types

**`VARIES`** is not a token type. It reports where a group's members
disagree in something no detector tokenised — `Unreachable` folded with
`Timeout` on similarity, a bare `board` folded with `<FQDN>`, `+sdown` with
`<FLAG>` — and the group's `normalized` template shows `<VARIES>` there, so
the shown line never claims a word half the members lack. A placeholder on
one side is a claim the other side breaks, so it varies too. A shared field
name stays in front of the slot (`msg=<VARIES>`, `"NodeName":<VARIES>`), and
a quoted value with spaces in it is one slot (`controller=<VARIES>`). Every
member's value is counted (`sample_counts`), and the samples are the most
frequent ones plus the rarest: `Server Busy` ×7,164 with one `Server Reject`
is visible as `["Busy","Reject"]` / `[7164, 1]`, not as "distinct_count 2".
Members with a different word count are aligned by longest common
subsequence; a template word a member has no counterpart for varies and is
counted as `∅`. A line that disagrees with a group's founder in two or more
words of the sentence — the verb and the outcome, `Synchronization … succeeded`
beside `Connection … lost.` — is not folded into it at all: one differing
word is a name or a value, two are another event.

**Sample-worthy** (identity types — samples are useful): `UUID`,
`IPV4`, `IPV6`, `MAC`, `HOST`, `PATH`, `EMAIL`, `HASH`, `K8S_NAMESPACE`, `K8S_VOLUME`,
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
    "ports": 1204,
    "hashes": 8734,
    "uuids": 2891,
    "pids": 421,
    "durations": 1832,
    "http_status": 0,
    "sizes": 15,
    "percentages": 3401,
    "paths": 23811,
    "json": 88,
    "quoted_strings": 412,
    "names": 96,
    "brackets": 1031,
    "key_values": 2210,
    "log_modules": 14,
    "structured": 7,
    "kubernetes": 312,
    "emails": 0,
    "macs": 0
  },
  "completeness": {
    "complete": false,
    "input": {
      "complete": true,
      "processed_lines": 73421,
      "skipped_overlong_lines": {"value": 0, "kind": "exact"},
      "unprocessed_after_max_lines": {"value": 0, "kind": "exact"},
      "failed_sources": {"value": 0, "kind": "exact"}
    },
    "groups": {
      "complete": true,
      "emitted": 2841,
      "total": {"value": 2841, "kind": "exact"},
      "omitted_by_top": {"value": 0, "kind": "exact"},
      "omitted_by_summary_cap": {"value": 0, "kind": "exact"},
      "omitted_by_fit": {"value": 0, "kind": "exact"}
    },
    "variation_values": {
      "complete": false,
      "capped_entries": 3,
      "sampled_entries": 87,
      "uncomputed_groups": 12,
      "omitted_values": {"value": null, "kind": "unknown"}
    }
  }
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `type` | string | Always `"summary"`. |
| `input_lines` | integer | Lines accepted for folding. Consult `completeness.input` for skipped or unread input. |
| `output_lines` | integer | Total lines in the formatted output (sum of lines per flushed group record — one line per group in JSON mode). |
| `compression_ratio` | number | `(lines_saved / input_lines) * 100`. Zero if no compression. |
| `collapsed_groups` | integer | Number of groups with `count >= min_collapse`. |
| `lines_saved` | integer | Total lines folded away by grouping. One definition across every output mode: each collapsed group preserves 3 lines (first + marker + last), so it saves `count - 3`. Agrees with the text-mode footer and `--stats-json` for the same input; derive any other measure from per-record `count`. |
| `patterns_detected` | integer | Total number of lines where at least one pattern token was detected. |
| `elapsed_ms` | integer | Wall-clock milliseconds from start of processing. **This is the only intentionally non-deterministic field.** Diff tools should exclude it when comparing runs. |
| `pattern_hits` | object | Per-category token-hit counts, one key per token type (nothing is lumped — ports, json, quoted_strings, names, brackets, key_values, log_modules and structured each have their own counter since v0.5). Keys are lowercase category names shared with `--stats-json`. |
| `completeness` | object | Document-level contract for omitted input, groups, and variation values. `complete` is true only when all three sections are complete. |

### Completeness and count kinds

Every omission count is an object with `value` and `kind`:

1. `exact`: `value` is the complete count.
2. `lower_bound`: at least `value` items were omitted; more may exist.
3. `unknown`: the remainder cannot be counted without consuming data that the selected limit intentionally stopped reading, so `value` is null.

`input` reports exact overlong-line skips, an unknown remainder after
`--max-lines`, and failed input sources. `groups` reports exact omissions from
`--top`, the 30-pattern JSON `--summary` cap, and `--fit`. `variation_values`
aggregates bounded samples and rollup caps; groups below `--min-collapse` have
no computed rollup and therefore make the omitted-value count unknown.

`--summary --format json` remains JSONL: it emits at most 30 ordinary group
records followed by this summary record. Omit `--summary` when every group
must be emitted.

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

A capped entry means at least `distinct_count` distinct values; the full
variation was not retained. These patterns are worth investigating:

```bash
lessence --format json prod.log \
  | jq -r 'select(.type == "group")
           | .variation
           | to_entries[]
           | select(.value.capped == true)
           | "\(.key): ≥\(.value.distinct_count)"'
```

## Known limitations

- **Retained unequal-length shapes have a cap.** Similar lines rejoin a
  retained group after eviction using the same founder matching rule as
  live groups. Most value counts accumulate directly. Members whose word
  count differs need alignment against the final template; up to 64
  distinct normalized forms are kept with occurrence counts. Beyond that,
  `VARIES` reports `capped: true`, a zero lower bound, and empty `samples`
  and `sample_counts`, because partial counts would be misleading. The
  group's occurrence count and other token rollups remain available.
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

## `Briefing` schema

The orientation block an agent should read before deciding what to run next.
It appears in two places, both from the same struct so they can never drift:

1. **`lessence --preflight <log>`** — the `Briefing` printed directly as the
   entire stdout JSON document (not wrapped in a record; there is no other
   `--preflight` output).
2. **`--explain`'s (`--format json --explain`) summary record**, under a new
   `briefing` field alongside `input_lines`, `pattern_hits`, etc.

`--preflight` used to print a `PreflightReport` — four duplicate
`estimated_compression` figures and an always-empty `sample_patterns` array.
That type and its stderr "# lessence Compression Report" markdown table are
both gone; `Briefing` replaces them everywhere.

```json
{
  "source": "kubelet.log",
  "lines": 3951,
  "span": {
    "first": "E0909 13:07:09.181236",
    "last": "E0920 14:52:55.728948",
    "duration_seconds": 956746,
    "lines_per_second": 0.004129622700277817
  },
  "format": {"json": 0, "logfmt": 50, "plain": 3901, "dominant": "plain", "mixed": false},
  "levels": {
    "fatal": 0, "error": 1044, "warn": 48, "info": 2681, "debug": 0, "trace": 0,
    "lines_with_level": 3773
  },
  "templates": {
    "total_groups": 248,
    "shown": [
      {
        "count": 713,
        "pct": 18.046064287522146,
        "template": "<TIMESTAMP>    <PID> reconciler_common.go:<LINE>] \"operationExecutor...\"",
        "first_epoch": 1788986556,
        "last_epoch": 1789897999,
        "span_seconds": 911443
      }
    ],
    "shown_share_pct": 52.09,
    "truncated": false,
    "singletons": 34,
    "singleton_pct": 0.86
  },
  "tokens": [
    {"class": "uuids", "occurrences": 5352, "distinct": 314, "distinct_exact": true}
  ],
  "histogram": {
    "bucket_seconds": 924398,
    "buckets": [441, 30, 30, 95],
    "busiest_index": 0,
    "busiest_count": 441,
    "busiest_pct": 23.824959481361425
  }
}
```

### Field reference

| Field | Type | Description — what to DO with it |
|---|---|---|
| `source` | string \| null | Input filename, or `null` for stdin. |
| `lines` | integer | Total input lines. |
| `span.first` / `span.last` | string \| null | Raw first/last timestamp string, unparsed. `null` on both when no line carried a recognised timestamp — nothing else in `span` is meaningful then. |
| `span.duration_seconds` | integer \| null | `last - first` in seconds. `null` when either endpoint is missing or the pair is unparseable. |
| `span.lines_per_second` | number \| null | `lines / duration_seconds`. `null` when duration is `null` or 0. A low rate on a long span (kubelet: 0.004 lines/s over 11 days) says this is a sparse control-plane log, not a busy one — don't expect a hot loop. |
| `format.json` / `.logfmt` / `.plain` | integer | Line counts by surface format. |
| `format.dominant` | string | `"json"`, `"logfmt"`, or `"plain"` — the largest of the three. Decide `jq` vs `awk`/`grep` from this before the first command. |
| `format.mixed` | boolean | `true` when more than one format is present in meaningful proportion — a single pipeline won't parse every line uniformly. |
| `levels.fatal`/`error`/`warn`/`info`/`debug`/`trace` | integer | Counts by severity. |
| `levels.lines_with_level` | integer | How many lines carried a recognisable level at all — the denominator for the per-severity percentages, and usually less than `lines`. Compare it to `lines`: a low ratio means most lines are unleveled and a `grep -i error` sweep alone will miss context. |
| `templates.total_groups` | integer | Total distinct templates found, shown or not. |
| `templates.shown` | array | Up to 10 templates, by count descending, each with `count`, `pct` (of all lines), `template`, and `first_epoch`/`last_epoch`/`span_seconds` (all `null` together when no member carried a timestamp). `span_seconds: 0` means every member landed in the same second — read as "in <1s" (an instant, likely one triggering event); a large `span_seconds` means "over &lt;duration&gt;" (routine, recurring). Rank by `span_seconds`, not `count`, to find the one-off among the housekeeping. |
| `templates.shown_share_pct` | number | Percent of all lines the shown templates account for together. |
| `templates.truncated` | boolean | `true` once distinct templates exceeded the internal cap (8192) — `total_groups` undercounts past that point. |
| `templates.singletons` | integer | Templates occurring exactly once — the tail the top-10 table can't show. Nonzero means there is rare signal worth a second pass even after reading the top templates. |
| `templates.singleton_pct` | number | Percent of all lines the singletons account for. |
| `tokens` | array | One entry per token class with `occurrences > 0`, sorted by occurrences descending. `class` is a lowercase name (`uuids`, `paths`, `ips`, ...). |
| `tokens[].occurrences` | integer | Total times this class appeared across all lines. |
| `tokens[].distinct` | integer | Distinct values seen — exact while `distinct_exact` is `true`; an HLL estimate (accurate to a few percent) once the class crosses 2048 distinct values. |
| `tokens[].distinct_exact` | boolean | `false` marks an HLL estimate (rendered with a `~` in text mode). |
| `histogram` | object \| null | `null` when `span.duration_seconds` is `null` — a histogram needs a clock. Otherwise a run-length time histogram, oldest-first, at most 24 buckets spanning `span.first..=span.last`. |
| `histogram.bucket_seconds` | integer | Width of each bucket in seconds. |
| `histogram.buckets` | array of integers | Line count per bucket, oldest first. |
| `histogram.busiest_index` | integer | Index into `buckets` of the busiest one. |
| `histogram.busiest_count` | integer | Its line count. |
| `histogram.busiest_pct` | number | That count as a percent of all bucketed lines. |

### Year inference

`span.duration_seconds` and the histogram's bucket placement are unaffected by
the source format's year handling. Two raw timestamp shapes carry no year of
their own — klog/glog (`E0909 13:07:09`) and syslog BSD (`Sep  9 13:07:09`) —
so `epoch_seconds` stamps them with the current UTC year to place them on a
clock; the duration/histogram arithmetic is correct regardless, since it only
needs a consistent clock, not the *right* year. The text renderer's busiest-
bucket label reflects this: `--preflight`'s JSON has no such label to worry
about (it reports only the epoch-derived numbers above), but the stderr
briefing's `shape:` line prints `MM-DD HH:MM` instead of `YYYY-MM-DD HH:MM`
for a year-less source, rather than printing an inferred year as if the log
had stated it.

## See also

- `docs/rollup-calibration.md` — methodology and evidence for the
  rollup constants (`ROLLUP_K`, `ROLLUP_DISTINCT_CAP`,
  `ROLLUP_TEXT_SAMPLE_THRESHOLD`).
- `docs/bench.md` — how to run the performance benchmarks.
- `.ideas/structured-folding-output-for-agents.md` — design
  rationale for the feature.
