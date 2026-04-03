---
name: lessence
description: >-
  Find the essence of massive logs. lessence ("log essence") folds repetitive lines
  and reveals error patterns. Use when: checking logs, anything not normal, wall of
  logs, too much output, can't find the error, what's the pattern, kubectl logs,
  docker logs, CI failures, crash loops, test failures, compress logs, journalctl.
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

# Start here for large logs
lessence --summary < app.log          # one-line-per-pattern (caps at 30, use --top N to adjust)
lessence --preflight < app.log        # JSON stats for automation/CI

# Key flags
lessence --essence < app.log          # strip timestamps, show pure patterns
lessence --top 10 < app.log           # top 10 most frequent patterns
lessence -q < app.log                 # suppress stats footer
lessence --format markdown < app.log  # markdown for incident reports
lessence --stats-json < app.log       # machine-readable stats on stderr
```

**For large logs, start with `--summary`** — caps at 30 patterns by default
with a coverage percentage. Use `--top N` to adjust or `--top 0` for all.
Then drill into specific patterns with default mode.

## Reading the Output

```
ERROR [handler-3] Failed to connect to 10.0.1.50:5432 - timeout
  [+847 similar, varying: TIMESTAMP, IP, PORT]
WARN [pool-1] Connection pool exhausted
  [+312 similar, varying: TIMESTAMP]
INFO [auth] Login succeeded user="admin@corp.com"
```

- **`[+N similar]`** = repeated N more times. High N = repeating problem.
- **`varying: TYPE`** = what changed between repetitions (TIMESTAMP, IP, etc.)
- **Few groups** = one dominant problem (focused debugging)
- **Many groups** = diverse issues (investigate each group)
- **Lines WITHOUT `[+N similar]`** = unique events — often the actual root cause

## Triage Workflows

### Quick triage (most common)
```bash
lessence -q < app.log | grep -i error
```
This single command compresses then filters — finds errors buried in any
volume of logs. Start here unless exploring unknown patterns.

### Full pipeline (for investigation)
```bash
# 1. Worth compressing?
lessence --preflight < app.log

# 2. Pattern overview (caps at 30 patterns, truncates long lines in terminal)
lessence --summary -q < app.log

# 3. Find errors specifically
lessence -q < app.log | grep -i error

# 4. Full compressed view when needed
lessence < app.log
```

### Crash-looping pod
```bash
kubectl logs deploy/api --previous | lessence --summary -q
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
# lessence works on JSON but output is unreadable (1500-char JSON lines).
# Extract key fields first, then compress:
kubectl logs deploy/app | jq -r '[.level, .method, .status, .path] | @tsv' \
  | lessence --summary --top 10 -q
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

## Interpreting Results — Common Mistakes

- **"Only 5 groups, compression looks too aggressive"** — this usually means
  the logs genuinely have only 5 distinct patterns. Check `--stats-json` for
  exact counts. High compression is a feature, not a bug.
- **"The error I'm looking for didn't appear"** — likely filtered out by
  `--top N`. Run without `--top` or pipe through `grep` after compression.
- **"`[+N similar, varying: IP]`" — is this N different clients?** — not
  necessarily. lessence groups by normalized pattern, not by IP value. The
  varying IPs might be load balancer health checks from the same source.
- **Essence mode may have no effect** — if timestamps are already well-normalized
  by default mode, `--essence` won't change grouping. It only helps when
  timestamps are the sole differentiator between otherwise-identical lines.
- **Short lines dominate --top** — logs with embedded JSON fragments produce
  high-frequency noise patterns like `],` or `}` that push real messages
  out of `--top N`. Use `grep -v '^.\{0,10\}$'` to filter first, or
  increase N.

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
