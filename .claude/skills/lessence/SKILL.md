---
name: lessence
description: >-
  lessence ("log essence") compresses repetitive log lines into patterns while
  preserving every unique line. Finds the essence of massive logs — the signal
  without the noise.
when_to_use: >-
  Triggers on "checking logs", "wall of logs", "too much output", "can't find
  the error", "what's the pattern", "compress logs", "feed logs to LLM",
  "reduce context", or when looking at kubectl logs, docker logs, journalctl
  output, CI failures, crash loops, test failures, or anything not normal in
  log output. Use for triage of any large log.
license: MIT
---

# lessence — Extract the Essence of Your Logs

lessence ("log essence") finds the essence of massive log output. Pipe
thousands of lines through it and get back the distinct patterns with
counts — the signal without the noise. It normalizes variable parts
(timestamps, IPs, UUIDs, hashes, PIDs), groups similar lines, and folds
duplicates into a representative line + count.

## The Decision: lessence vs grep

Use the right tool for the job:

| Situation | Tool | Why |
|-----------|------|-----|
| Error keyword is known ("error", "panic") | `grep -i error` | Faster, simpler |
| Unknown what to search for | `lessence` | Reveals patterns that weren't anticipated |
| Need to understand the shape of failures | `lessence` | Shows frequency distribution across error types |
| Huge output but one known needle | `grep` | Don't compress when filtering suffices |
| Huge output, unknown number of problems | `lessence` then `grep` on compressed output | Compress first, then drill in |
| Comparing two log periods | `lessence --essence` + `diff` | Strips timestamps for structural comparison |

**Not for**: small output (<50 lines), binary data, exact counting (`grep -c`).
For structured JSON logs, preprocess with `jq` first (see JSON workflow below).

## Core Commands

```bash
lessence app.log                      # compress a file
kubectl logs deploy/api | lessence    # pipe anything through it
cargo test 2>&1 | lessence            # capture stderr too

# Start here — one screen, no scrolling
lessence --human < app.log            # fits terminal height, implies --summary
lessence --summary < app.log          # one-line-per-pattern (caps at 30, use --top N to adjust)
lessence --preflight < app.log        # JSON stats for automation/CI

# Feed compressed logs to an LLM
kubectl logs pod/api | lessence | claude -p "what's wrong?"
kubectl logs pod/api | lessence --format json | claude -p "analyze this structured log report"

# Key flags
lessence --essence < app.log          # strip timestamps, show pure patterns
lessence --top 10 < app.log           # top 10 most frequent patterns
lessence -q < app.log                 # suppress stats footer
lessence --format markdown < app.log  # markdown for incident reports
lessence --format json < app.log      # JSONL with rollup metadata (best for agents)
lessence --stats-json < app.log       # machine-readable stats on stderr
```

**For large logs, start with `--human`** (alias `--fit`) — adapts output to
terminal height so results stay visible after the command returns. For a
specific count, use `--summary --top N`. Then drill into specific patterns
with default mode.

**For agent/programmatic use, prefer `--format json`** over text mode. The
JSON output carries per-group rollup metadata (distinct counts, sample
values, time ranges) that lets agents answer follow-up questions without
re-running the tool. See "Structured JSON Output" below.

## Reading the Output

### Text mode (default)

```
ERROR [handler-3] Failed to connect to 10.0.1.50:5432 - timeout
[+847 similar | 13:07:09 → 14:52:33 | ipv4×4, port×2 {5432, 6379}]
ERROR [handler-3] Failed to connect to 10.0.1.99:6379 - timeout
WARN [pool-1] Connection pool exhausted
[+312 similar | duration×1]
INFO [auth] Login succeeded user="admin@corp.com"
```

- **`[+N similar]`** = repeated N more times. High N = repeating problem.
- **`13:07:09 → 14:52:33`** = time range of the group (first and last timestamp).
- **`ipv4×4`** = 4 distinct IP addresses in this group. Low count = narrow problem; high count = widespread.
- **`port×2 {5432, 6379}`** = only 2 distinct ports, both shown inline (complete set).
- **`hash×1024+`** = the distinct-value cap was hit. The `+` means "at least 1024 and possibly many more."
- **Few groups** = one dominant problem (focused debugging)
- **Many groups** = diverse issues (investigate each group)
- **Lines WITHOUT `[+N similar]`** = unique events — often the actual root cause

### JSON mode (`--format json`)

Each folded group is a JSON object on one line (JSONL). The last record
is a `"summary"` with aggregate statistics. Key fields per group:

```json
{
  "type": "group",
  "count": 847,
  "normalized": "ERROR [handler-<NUMBER>] Failed to connect to <IP>:<PORT>...",
  "time_range": {"first_seen": "13:07:09", "last_seen": "14:52:33"},
  "variation": {
    "IPV4": {"distinct_count": 4, "samples": ["10.0.1.50", "10.0.1.51", "10.0.1.99", "10.0.2.1"], "capped": false},
    "PORT": {"distinct_count": 2, "samples": ["5432", "6379"], "capped": false}
  }
}
```

- **`variation`** — per-token-type distinct counts and sample values. This is the key field for triage: agents can answer "which IPs?", "how many distinct UUIDs?", "which namespaces?" from a single invocation.
- **`samples`** — up to 7 values, deterministic (same input = same samples across runs). Empty for count-only types (TIMESTAMP, NUMBER, DURATION).
- **`capped: true`** — distinct_count is a lower bound (at least 64 and possibly more).
- **`normalized`** — the template with `<TOKEN>` placeholders; this is what lessence groups by.

Full schema: `docs/format-json-schema.md`.

## Agent Triage Pipeline

For agent-driven triage, pair `--format json` with `jq`. The JSON
output carries per-group rollup metadata (distinct counts, sample
values, time ranges) so follow-up questions resolve from the saved
summary without a second `lessence` invocation.

```bash
# Step 1: get the structured summary
lessence --format json < app.log > /tmp/summary.jsonl

# Step 2: answer specific questions from the summary
# Which groups have the most distinct IPs? (broad vs narrow problem)
jq -r 'select(.type == "group") | "\(.count)x | IPs: \(.variation.IPV4.distinct_count // 0) | \(.normalized[:80])"' /tmp/summary.jsonl

# Which pods are affected?
jq -r 'select(.type == "group" and .count >= 100) | .variation.K8S_POD.samples // [] | .[]' /tmp/summary.jsonl

# When did this pattern start?
jq -r 'select(.type == "group" and .count >= 50) | "\(.time_range.first_seen) — \(.normalized[:60])"' /tmp/summary.jsonl

# Which patterns hit the distinct-value cap? (high-cardinality → investigate)
jq -r 'select(.type == "group") | .variation | to_entries[] | select(.value.capped) | "\(.key): >=\(.value.distinct_count)"' /tmp/summary.jsonl

# Overall compression stats
jq 'select(.type == "summary") | {input_lines, output_lines, compression_ratio}' /tmp/summary.jsonl
```

Output is deterministic (same input → byte-identical output except
`elapsed_ms`), safe to cache, and streamable — JSONL parses line by
line.

## Triage Workflows

### Quick triage (most common)
```bash
lessence -q < app.log | grep -i error
```
This single command compresses then filters — finds errors buried in any
volume of logs. Start here unless exploring unknown patterns.

### Full pipeline (for investigation)
```bash
# 1. One screen overview
lessence --human < app.log

# 2. Worth compressing further?
lessence --preflight < app.log

# 3. Find errors specifically
lessence -q < app.log | grep -i error

# 4. Full compressed view when needed
lessence < app.log

# 5. Structured triage (agent-friendly)
lessence --format json < app.log | jq 'select(.type == "group" and .count > 100)'
```

### Crash-looping pod
```bash
kubectl logs deploy/api --previous | lessence --human
# Then drill in:
kubectl logs deploy/api --previous | lessence -q | grep -i error
```

### CI build failure buried in noise
```bash
# DON'T use --top alone — frequent patterns are noise (warnings),
# the actual error may appear only once. Instead:
lessence -q < build.log | grep -i "error"
```

### JSON logs (jq then lessence)
```bash
# When INPUT is structured JSON, extract key fields first:
kubectl logs deploy/app | jq -r '[.level, .method, .status, .path] | @tsv' \
  | lessence --summary --top 10 -q

# Or use --format json for structured OUTPUT (input can be any format):
kubectl logs deploy/app | lessence --format json \
  | jq 'select(.type == "group" and .count > 50) | {count, template: .normalized[:80]}'
```

### Tabular/columnar output (DB stats, RocksDB, vmstat)
```bash
# Default threshold (75) may over- or under-group tabular rows.
# Experiment with lower values:
lessence --threshold 50 --summary -q < stats.log
```

### Multi-source comparison
```bash
# Compare compression across multiple log sources
for f in /tmp/*.log; do
  echo -n "$(basename $f): "
  lessence --preflight "$f" | jq -r '.estimated_compression.default'
done

# Compare structure between pods
kubectl logs pod-a 2>&1 | lessence --essence > /tmp/a.txt
kubectl logs pod-b 2>&1 | lessence --essence > /tmp/b.txt
diff /tmp/a.txt /tmp/b.txt
```

### CI gating
```bash
lessence --fail-on-pattern "ERROR|FATAL" < app.log
# Exit code 1 if pattern found, 0 if clean
```

## Pitfall: --top N Can Hide the Signal

`--top N` shows the N **most frequent** patterns. In noisy logs, the most
frequent lines are often the harmless ones (warnings, health checks, info
spam). The actual error may appear only once and get excluded.

**Use `--top` for**: understanding the dominant behavior, finding the
repeating problem in crash loops, capacity planning.

**Don't use `--top` for**: finding a needle in a haystack. Use plain
`lessence` or `lessence -q | grep error` instead.

## Common Mistakes

- **"Compression too aggressive"** — high compression means few distinct patterns. Check `--stats-json` for exact counts.
- **"Error didn't appear"** — `--top N` excludes rare lines. Run without `--top` or pipe through `grep`.
- **"`varying: IP` — different clients?"** — not necessarily. lessence groups by pattern, not by value. Varying IPs may be the same source.
- **"--essence had no effect"** — only helps when timestamps are the sole differentiator between lines.
- **"Short lines dominate --top"** — JSON fragments like `],` or `}` are high-frequency noise. Filter with `grep -v '^.\{0,10\}$'` first, or increase N.

## Reference

- **`references/flags.md`** — Complete flag reference including security limits
  (`--sanitize-pii`, `--max-line-length`, `--max-lines`), pattern control
  (`--threshold`, `--min-collapse`, `--disable-patterns`), and CI integration
  (`--fail-on-pattern`). Consult when needing a flag beyond the core set above.

## Installation

```bash
cargo binstall lessence   # prebuilt binary
cargo install lessence    # from source
```

Available for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows.
