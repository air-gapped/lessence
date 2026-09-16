---
name: lessence
description: >-
  lessence ("log essence") compresses repetitive log lines into patterns while
  preserving every unique line. Finds the essence of massive logs — the signal
  without the noise. Use it instead of tail/head/grep sampling when diagnosing
  any large log: tail -50 is bounded but blind to the rest of the file;
  lessence declares anything it omits.
when_to_use: >-
  Triggers on "checking logs", "wall of logs", "wall of text", "build log",
  "too much output", "can't find the error", "what's actually failing",
  "find the root cause", "the error happened earlier", "what's
  the pattern", "compress logs", "feed logs to LLM", "reduce context", or
  when looking at kubectl logs, docker logs, journalctl output, CI failures,
  crash-looping pods, test failures, or anything not normal in log output.
  When tempted to tail -N, head -N, or sample a log over ~200 lines to keep
  output small: lessence -q is usually smaller than tail -200 and contains
  every unique line, and its output already reports line counts, level
  distribution and per-pattern time ranges (the briefing) — no wc/head/tail recon pass needed. Pipe logs through lessence
  FIRST — before reading them raw. Does NOT trigger for short output (under
  ~50 lines), live following (tail -f), or when the task is ONLY a
  known-keyword search — plain grep suffices there; if the question is even
  partly exploratory ("anything else weird?"), use lessence.
license: MIT
---

# lessence — Extract the Essence of Massive Logs

`tail -50` on a 40,000-line log shows 50 lines and silently hides the
rest — and the root cause is rarely in the last N lines. lessence
normalizes variable parts (timestamps, IPs, UUIDs, hashes, PIDs), groups
similar lines, and folds duplicates into a representative line + count,
so every distinct pattern stays visible. Fields that identify *what the
line is about* — the request target of an HTTP request, a PCI device
address — are matched exactly, never approximately, so a group's
representative names an endpoint and device its members really used.
When it does bound output
(`--summary`, `--top N`) it says how many patterns were omitted. Prefer
the view that declares its blind spots over the one that hides them.

No recon pass needed first: the briefing reports line counts and
each folded group carries its time range, so `wc -l` / `head -3` /
`tail -3` scoping before running lessence is redundant — start with
lessence directly.

## The Decision: lessence vs grep vs tail

Use the right tool for the job:

| Situation | Tool | Why |
|-----------|------|-----|
| Question is ONLY a known keyword ("show panics") | `grep -i panic` | Faster, simpler |
| Keyword known but question partly exploratory ("...and anything else weird?") | `lessence -q`, then grep the folded output | Keywords answer half; patterns reveal the rest |
| Unknown what to search for | `lessence` | Reveals patterns that weren't anticipated |
| Need to understand the shape of failures | `lessence` | Shows frequency distribution across error types |
| Only the latest events matter (problem is live right now) | `tail -N` | Recency is the filter — legitimate tail |
| Failure location in the file unknown | `lessence -q` | Root cause is rarely in the last N lines |
| Tempted to tail/head/sample "to save context" | `lessence -q` | Usually fewer lines than `tail -200`, zero blind spots |
| Huge output, unknown number of problems | `lessence` then `grep` on compressed output | Compress first, then drill in |
| Comparing two log periods | `lessence --essence` + `diff` | Strips timestamps for structural comparison |

**Not for**: small output (<50 lines), binary data, exact counting (`grep -c`).
Structured JSON logs fold natively — distinct `msg`/field values each keep their
own group. Use the jq workflow below only to project specific fields.

## Core Commands

```bash
lessence app.log                      # compress a file
kubectl logs deploy/api | lessence    # pipe anything through it
cargo test 2>&1 | lessence            # capture stderr too

# Agent-friendly output (prefer these when piping into Claude)
lessence --format json < app.log      # JSONL with rollup metadata — best for follow-up jq queries
lessence --preflight < app.log        # orientation briefing as JSON (no folded output)
lessence --stats-json < app.log       # machine-readable stats on stderr
lessence --summary < app.log          # compact one-line-per-pattern overview (caps at 30, use --top N to adjust)

# Key flags
lessence --essence < app.log          # strip timestamps, show pure patterns
lessence --top 10 < app.log           # top 10 most frequent patterns
lessence -q < app.log                 # suppress the briefing (it goes to stderr — stdout is always pipe-clean)
```

## Reading the Output

### The briefing (read this first, every time)

Every run — text mode, `--explain`, `--preflight` — starts by orienting you
before you decide what to run next. In text mode it's a stderr footer after
the folded output; `--preflight` prints the same facts as its entire JSON
document; `--explain`'s summary record carries it as `briefing`. `-q`
silences only the stderr rendering, never the JSON.

```
--- lessence briefing: kubelet.log (3,951 lines)
span:    E0909 13:07:09.181236 → E0920 14:52:55.728948  (11d 1h, 0.004 lines/s)
shape:   ▆▁▁▁ ▁ ▁ ▁█▁▁▁▁▁▁ ▁▁▂▁▁▁  busiest 09-14 03:51 +11h 4m holds 1,785 (46.6%)
format:  plain 3,901 (99%), logfmt 50 (1%)
levels:  error 1,044 (27.7%), warn 48 (1.3%), info 2,681 (71.1%) — on 3,773 lines (95%)
top templates (10 of 248, 52.1% of all lines):
    18%  713  over 10d 13h  <TIMESTAMP>    <PID> reconciler_common.go:<LINE>] "operationExecutor…
   ...
rare:    34 templates occur once (0.9% of lines)
tokens:  quoted_strings 8,090/798, timestamps 6,063/~4,778, uuids 5,352/314, paths 5,294/378, ...
---
```

Read it top to bottom, and let it decide the next command:

- **`format:`** decides `jq` vs `grep`/`awk` before you write the first
  command. `format: json 100%` on argocd means every downstream query is a
  `jq` one-liner; a mixed or plain-dominant log means `grep`/`awk`.
- **`levels:`** decides whether to read every error or fold within them.
  `error 31 (0.1%)` on argocd means read all 31 directly — no need to
  compress further. `error 8,000` means fold first, then grep.
- **`top templates`, the middle column (count over span), is the signal that
  separates routine from real.** On argocd: `22,527 over 5h 50m` is TLS-config
  housekeeping firing every few seconds for the entire run — background noise
  regardless of how large the count looks. `31 in <1s` a few rows down is the
  single restart event that actually answers "what happened" — every member
  landed within the same second. Ranking by count alone puts the housekeeping
  first and the answer last; always check the span column, not just the count.
- **`tokens:`** — `occurrences/distinct` per class decides whether a class is
  a facet or a correlation key:
  - **Low distinct relative to occurrences** (`uuids 5,352/314`, kubelet) is a
    facet: 314 pods, each recurring. Group by it — `jq` the `K8S_POD` samples,
    or grep one and expect many hits.
  - **Distinct near occurrences** (`uuids 46,662/~46,001`) is a per-request
    correlation key: almost every occurrence is a different value. Pull one
    failing line's id and grep that exact id across the file — the
    investigation is usually over in one command, because that id threads
    through every log line the same request touched.
  - `~` before the distinct count means it's an HLL estimate (crossed 2048
    distinct values) — accurate to a few percent, still fine for this
    low/high judgment call.
- **`rare:`** — nonzero means there's a tail the top-10 table can't show;
  worth a look even after reading the dominant templates.

Full field reference (every field, every type, both JSON locations):
`docs/format-json-schema.md`, "`Briefing` schema".

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
- **`hash×64+`** = the distinct-value cap (64) was hit. The `+` means "at least 64 and possibly many more."
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

- **`variation`** — per-token-type distinct counts and sample values. This is the key field for triage: agents can answer "which IPs?", "how many distinct UUIDs?", "which namespaces?" from a single invocation. Hostnames appear under their own `FQDN` key since 0.4.4 (older versions mislabeled them `IPV4`). A syslog/journal line's positional host — `<TIMESTAMP> gw-core dnsmasq[<PID>]:` — folds to `<HOST>` and appears under its own `HOST` key, so the same event from several devices is one group.
- **`samples`** — up to 7 values, deterministic (same input = same samples across runs). Empty for count-only types (TIMESTAMP, NUMBER, DURATION).
- **`VARIES`** — where a group's members disagree in something no detector tokenised (`Unreachable` vs `Timeout`, `Busy` vs `Reject`, a bare word vs a placeholder); the group's `normalized` shows `<VARIES>` there, keeping a shared field name in front (`msg=<VARIES>`) and treating a quoted value with spaces as one slot. Its `samples` are ordered by `sample_counts` (most frequent first, the rarest last), so a 1-in-7,000 outcome is visible without reading the raw lines; `∅` counts members that lack the word. Text mode shows the same as `varies×N {word×count, …}`. A line that differs from a group's founder in two or more sentence words (verb and outcome) founds its own group instead.
- **`capped: true`** — distinct_count is a lower bound. A retained group can also exceed the 64 distinct unequal-length shapes kept for final word alignment; its `VARIES` then has a zero lower bound and empty samples/counts rather than misleading partial counts. The group's occurrence count and other token rollups remain available.
- **`normalized`** — the template with `<TOKEN>` placeholders; this is what lessence groups by.
- **PCI devices** — exact PCI addresses such as `0000:21:00.0` stay visible because different addresses already keep hardware events apart. An address inside a normalized route is shown beside that route skeleton. An address embedded in a path stays visible when the surrounding path text varies.
- **Systemd unit subjects** — the template shows the unit identity: `modprobe@loop.service` and `modprobe@fuse.service` remain distinct; numeric instances show `<N>` and opaque hex/UUID runs show `<ID>`. Exact instance names remain in the `NAME` facts. Different instances of the same unit kind can still fold together. This applies when the unit is the subject immediately after `systemd[PID]:`, not to messages about starting a unit or to mount/device units.
- **HTTP requests** — when methods vary within a group, the quoted request keeps its route visible: `"<VARIES> /route HTTP/<DECIMAL>"`. The `VARIES` facts count methods such as `GET` and `POST`, rather than hiding the whole request. Protocol-version variation has its own slot. Prose requests such as `making POST http request: http://host/promote` and `GET https://host/items/42` keep method and route separate: `http://<HOST>/promote` or `https://<HOST>/items/<N>`. Hosts, object IDs and queries may vary; complete targets remain in `PATH` facts.
- **Event identity** — anchored call sites, Python traceback frames (file, line, function), and program fields such as `exe=` or `"binary":` stay literal in the template. They already keep different events apart; showing them makes the reason visible. Other file paths still normalize to `<PATH>`.
- **Audit syscall outcomes** — raw `type=SYSCALL msg=audit(...)` records keep `success=yes` and `success=no` in separate groups, with the outcome visible in the template. Repeated events with the same outcome can still fold across return values.
- **CLI options** — recognized long and single-letter option names in logged commands stay visible and keep different options in separate groups. Their values may vary, including inside quoted commands. Option names no longer appear as `PATH` samples. Repeated commands can still fold across revision hashes and execution IDs; single-dash words such as `-sdown` remain prose.
- **Status classes** — anchored JSON/logfmt status fields stay visible as `<STATUS_2XX>`, `<STATUS_4XX>`, and so on; their exact numeric codes remain in the numeric rollup. Quoted HTTP responses use `<HTTP_STATUS_2XX>`. Codes within one class (such as 200 and 204) can fold together; different classes stay separate. These class identities stay visible when token detection is disabled. A generic status field can also be a process exit code, so its marker does not label it as HTTP.

## Agent Triage Pipeline

Save `--format json` output once, then answer follow-up questions with
`jq` from the saved summary — no second `lessence` invocation needed.

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
# 1. Orient: span, format, levels, top templates, token cardinality
lessence --preflight < app.log

# 2. Compact overview (patterns + counts only)
lessence --summary -q < app.log

# 3. Full compressed view
lessence -q < app.log

# 4. Structured triage for follow-up jq queries
lessence --format json < app.log | jq 'select(.type == "group" and .count > 100)'
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
# Optional: to summarize only specific fields of structured JSON, project them first:
kubectl logs deploy/app | jq -r '[.level, .method, .status, .path] | @tsv' \
  | lessence --summary --top 10 -q

# Or use --format json for structured OUTPUT (input can be any format):
kubectl logs deploy/app | lessence --format json \
  | jq 'select(.type == "group" and .count > 50) | {count, template: .normalized[:80]}'
```

### Tabular/columnar output (DB stats, RocksDB, vmstat)
```bash
# Default threshold (83) may over- or under-group tabular rows.
# Experiment with lower values:
lessence --threshold 50 --summary -q < stats.log
```

### Multi-source comparison
```bash
# Compare error rate and template diversity across multiple log sources
for f in /tmp/*.log; do
  echo -n "$(basename $f): "
  lessence --preflight "$f" | jq -r '"error \(.levels.error) of \(.lines) lines, \(.templates.total_groups) distinct templates"'
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

## Common Mistakes

- **"Compression too aggressive"** — high compression means few distinct patterns. Check `--stats-json` for exact counts.
- **"Error didn't appear"** — `--top N` shows the N **most frequent** patterns, which in noisy logs are often the harmless ones; a one-off error gets excluded. `--top` is for dominant behavior (crash loops, capacity); for needle-in-haystack use plain `lessence -q | grep -i error`.
- **"`varying: IP` — different clients?"** — not necessarily. lessence groups by pattern, not by value. Varying IPs may be the same source.
- **"--essence had no effect"** — only helps when timestamps are the sole differentiator between lines.
- **"Short lines dominate --top"** — JSON fragments like `],` or `}` are high-frequency noise. Filter with `grep -v '^.\{0,10\}$'` first, or increase N.

## Reference

- **`references/flags.md`** — Complete flag reference including security limits
  (`--sanitize`, `--sanitize-pii`, `--max-line-length`, `--max-lines`), pattern control
  (`--threshold`, `--min-collapse`, `--disable-patterns`), and CI integration
  (`--fail-on-pattern`). Consult when needing a flag beyond the core set above.
- **`references/sources.md`** — Per-claim verification stamps against the repo's
  binary and docs. Consult when a claim looks stale; re-verify after user-facing
  `feat:`/`fix:` commits.
- **`references/trigger-evals.json`** — Persistent trigger eval set (10 should-fire,
  8 should-not). Used by skill-improver trigger mode; extend rather than replace.
- **`references/choice-evals/`** — Behavioral eval harness: does the model pick
  lessence over tail/grep on a real large-log diagnosis? See its README to
  re-run after skill or binary changes.
