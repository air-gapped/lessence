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
  output small: lessence -q is usually smaller than tail -200, its saved
  report holds every unique line, and its output already reports line counts, level
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
| Tempted to tail/head/sample "to save context" | `lessence -q` | Usually fewer lines than `tail -200`; the report keeps every group and the overview declares what it left out |
| Huge output, unknown number of problems | `lessence` then `grep` on compressed output | Compress first, then drill in |
| Comparing two log periods | `lessence --essence` + `diff` | Strips timestamps for structural comparison |

**Not for**: small output (<50 lines), binary data, exact counting (`grep -c`).
Structured JSON logs fold natively — distinct `msg`/field values each keep their
own group. Use the jq workflow below only to project specific fields.

## This skill and the binary

With this skill in context, everything `lessence --help` points to is already
loaded; do not run `lessence --skill` again.

The installed binary is the authority for syntax: `lessence --help` wins over
anything this text remembers. The skill ships inside the binary and was
verified against the build that prints it; after upgrading, reinstall it:

```bash
mkdir -p ~/.claude/skills/lessence/references
lessence --skill > ~/.claude/skills/lessence/SKILL.md
lessence --skill flags > ~/.claude/skills/lessence/references/flags.md
```

## Core Commands

```bash
lessence app.log                      # compress a file
kubectl logs deploy/api | lessence    # pipe anything through it
cargo test 2>&1 | lessence            # capture stderr too

# Agent-friendly output (prefer these when piping into Claude)
lessence --format json < app.log      # JSONL with rollup metadata — best for follow-up jq queries
lessence --explain app.log            # the same JSONL plus `nearest`: why a line founded its own group (references/flags.md)
lessence --preflight < app.log        # orientation briefing as JSON (no folded output; takes no --top/--summary/--fit/--explain/--stats-json)
lessence --stats-json < app.log       # machine-readable stats on stderr (same input_lines and ratio with --summary)
lessence --summary < app.log          # compact one-line-per-pattern overview (caps at 30, use --top N to adjust)

# The default run: complete report on disk, bounded overview on stdout
lessence app.log                      # overview on stdout; the head locator names the report file
lessence --overview all app.log       # every group, no byte budget
lessence --no-report app.log          # no file: stream the folded text, as before (use for `tail -f`)

# Key flags
lessence --essence < app.log          # strip timestamps, show pure patterns
lessence --top 10 < app.log           # top 10 most frequent patterns (--top 0 = all)
lessence -q < app.log                 # drop the briefing block (in --no-report runs it is a stderr footer)
lessence --frame-continuations < app.log   # a stack trace folds as one event, not one group per frame
lessence --sanitize host:pseudonym,ip < app.log   # mask hosts and IPs; pseudonym tags keep folding (references/flags.md)
```

## Reading the Output

### The saved report and the overview (default runs)

A default run writes the complete folded JSON of the run — the same schema-1
records `--format json` emits — to `report.jsonl` in a fresh run directory, and
prints a byte-bounded overview of it on stdout (16 KiB by default). Nothing is
lost: the report is complete, stdout is bounded and says so.

```
report: ~/.local/state/lessence/reports/run-20260919-161814-f1362b46/report.jsonl  file: complete  input: complete  run: run-…  size: 673464 bytes  groups: 254 total, 40 selected, 15 printed, 239 omitted
```

That locator line follows the briefing (under `-q` it is the first line) and
repeats after the last entry, above the jq recipes, so a truncated capture
keeps one of them. `printed < selected` means the byte
budget stopped the entries early — the report still has every group. The four
jq recipes at the end query the file by group id; none of them cats it.

An entry declares its omissions in two separate registers: `previewed here`
is what this screen cut, `report-sampled` on the `variation:` line is what the
report itself does not hold. `ip=9` is an exact distinct count, `ip>=64` a
lower bound, and `variation: not recorded` means no rollup was computed for
that group, or it had nothing to vary.

An entry's first line is its count, id and time range; a group whose lines
bunch in time adds where most of them fell, exactly as the text marker does
(see Text mode):

```
[100x] id=0 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55–16:58
[480x] id=1 2026-09-09T09:00:02Z → 2026-09-09T16:59:02Z
```

`--overview all` prints every group with no budget and no preview cuts (it
streams: peak memory is one record, whatever the group count).
`--overview 0` prints the locators and recipes only. `--no-report` turns the
whole thing off and streams the folded text as before — **use it for `tail -f`
or any source that never reaches EOF**, since the report needs input EOF.
It is harmless in every other mode (`--format json`, `--summary`, `--top`,
`--preflight`, …): they save no report, so there it does nothing.
The report directory is never pruned: it grows until it is deleted.
If stdout is empty and the exit code is 1 with `report: not written (…)` on
stderr, the report directory is on memory-backed storage (tmpfs) or the report
passed `--report-max-bytes`: rerun with `--report-dir DIR` on disk, or
`--no-report` for the folded text alone.
See references/flags.md for `--report-dir`, `--report-max-bytes` and the rest.

### The briefing (read this first, every time)

Every run — text mode, `--explain`, `--preflight` — starts with the facts that decide the
next command. In a default run it is the first block of
the stdout overview; under `--no-report` it is a stderr footer after the folded
output; `--preflight` prints the same facts as its entire JSON document;
`--explain`'s summary record carries it as `briefing`. `-q` drops that rendered
block — on stdout in a default run, on stderr under `--no-report` — and never
touches the JSON.
In the JSON, `span.year_inferred: true` means the stamps (klog, BSD syslog) carry no year and the epochs assume the current one: use them for differences and ordering, not as absolute dates.

```
--- lessence briefing: kubelet.log (749 lines)
span:    E0909 13:07:09.181236 → I0920 08:26:00.404337  (10d 19h, 0.001 lines/s)
shape:   █▁▁▁     ▁█▁       ▁▁ ▁▁  busiest 09-09 13:07 +10h 48m holds 317 (47.9%)
format:  plain 728 (97%), logfmt 21 (3%)
levels:  error 252 (38.9%), warn 19 (2.9%), info 376 (58.1%) — on 647 lines (86%)
top templates (10 of 224, 18.4% of all lines):
   8.7%  65  over 4d 20h   <TIMESTAMP>    <PID> reconciler_common.go:159] "operationExecutor…
   ...
rare:    26 templates occur once (3.5% of lines)
tokens:  quoted_strings 945/227, timestamps 913/733, uuids 683/74, kubernetes 656/150, ...
---
```

Read it top to bottom, and let it decide the next command:

- **`format:`** decides `jq` vs `grep`/`awk` before the first command is
  written. `format: json 100%` on argocd means every downstream query is a
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
  - **Low distinct relative to occurrences** (`uuids 683/74`, kubelet) is a
    facet: 74 pods, each recurring. Group by it — `jq` the `K8S_POD` samples,
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
2026-09-09T13:00:09Z ERROR [handler-3] Failed to connect to 10.0.1.50:5432 - timeout
[+58 similar | 2026-09-09T13:00:09Z → 2026-09-09T13:59:09Z | ipv4×4, port×2]
2026-09-09T13:59:09Z ERROR [handler-3] Failed to connect to 10.0.1.53:6379 - timeout
WARN [pool-1] slow query took 3ms user=u1
[+38 similar | varies×2 {u0×20, u1×20}]
WARN [pool-1] slow query took 120ms user=u0
INFO [auth] Login succeeded user="admin@corp.com"
```

A folded group prints its first member, the marker, then its last member.

- **`[+N similar]`** = N more members between the two shown lines. High N = repeating problem.
- **`… → …`** = the group's first and last timestamp, in the log's own stamp format.
- **`98% in 16:55–16:58`** = the group is bunched: almost all its lines fell in a short part of that range. Shown only when at least 90% of 10 or more timestamped members fall within a quarter of the group's own span (in buckets of the briefing's `shape:` grid, and in seconds); otherwise the marker carries no clause and the lines are spread over the range. Clock time when the group stays on one date, otherwise the date too. A group whose `first → last` reads like all day may be one burst:

  ```
  2026-09-09T09:00:00Z ERROR upstream refused connection from 10.1.2.1
  [+98 similar | 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55–16:58 | ipv4×4]
  2026-09-09T16:58:14Z ERROR upstream refused connection from 10.1.2.2
  ```
- **`ipv4×4`** = 4 distinct IP addresses in this group. Low count = narrow problem; high count = widespread.
- **`ipv4×2 {10.0.1.50, 10.0.1.51}`** = up to 3 distinct values are listed inline, and the list is then complete; from 4 up only the count shows — the values are in the JSON `samples`.
- **`port×2`** = count-only classes never list values.
- **`varies×2 {u0×20, u1×20}`** = an untokenised word that differs between members, each value with its member count.
- **A template with several `<VARIES>` slots lists one `varies×` per slot, in template order** — the first `varies×` is the first `<VARIES>`. Each slot keeps its own 64-value cap and its own most-frequent-plus-rarest samples, so a rare value in one slot is not crowded out by another:

  ```
  failed to start "db" on node "n1"
  [+2 similar | varies×2 {"db"×3, "cache"×1}, varies×4 {"n1"×1, "n2"×1, "n3"×1, "n4"×1}]
  failed to start "db" on node "n4"
  ```
- **`hash×64+`** = the distinct-value cap (64) was hit. The `+` means "at least 64 and possibly many more."
- **Few groups** = one dominant problem (focused debugging)
- **Many groups** = diverse issues (investigate each group)
- **Lines WITHOUT `[+N similar]`** = unique events — often the actual root cause

### JSON mode (`--format json`)

The final summary and `--preflight` include `schema_version: 1`, structured
`version` (semver/build/target), `input_hash`, and `degraded` with actionable
`code`, `count`, `message`, and `repair`. Check `degraded` before drawing a
conclusion from partial input: it names skipped overlong lines, a line-limit
cutoff, and exact failed-source counts. Empty `degraded` means input was
complete; output/sample limits still live in `completeness`.

`input_hash` identifies the ordered raw source bytes and boundaries, excluding
filenames; it is not a hash of the output or a standalone cache key. Its value
is null for sanitized, failed-source, or truncated runs, with an explicit
`unavailable_reason`. Overlong skipped bytes still contribute when all input
reached EOF. A missing final summary means no completion claim; inspect exit
status too. Library output without recorded ingestion uses `not_recorded`.
See the repo's `docs/format-json-schema.md` for the exact aggregate encoding.

Each folded group is a JSON object on one line (JSONL). The last record
is a `"summary"` with aggregate statistics. Key fields per group:

```json
{
  "type": "group",
  "count": 847,
  "normalized": "<TIMESTAMP> ERROR [handler-3] Failed to connect to <IP>:<PORT> - timeout",
  "time_range": {"first_seen": "2026-09-09T13:07:09Z", "last_seen": "2026-09-09T14:52:33Z"},
  "variation": {
    "IPV4": {"distinct_count": 4, "samples": ["10.0.1.50", "10.0.1.51", "10.0.1.99", "10.0.2.1"], "capped": false},
    "PORT": {"distinct_count": 2, "samples": [], "capped": false}
  }
}
```

- **`time_range.buckets`** — the group's timestamped members per time bucket, on the same grid as the briefing's `histogram` (`bucket_seconds` is the same, `buckets[i]` covers the same seconds as `briefing.histogram.buckets[i]`, from `span.first`), so a group's share of any stretch of the log is one division. Present when at least 3 members carry a timestamp and they fall in more than one bucket. `bunched` (only on a bunched group) is the text clause as data: `first_bucket`/`last_bucket`, `members` in that run, `pct`, and `from`/`to` as the clause writes them:

  ```json
  "time_range": {"first_seen":"2026-09-09T09:00:00Z","last_seen":"2026-09-09T16:58:14Z","bucket_seconds":1198,"buckets":[1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,98],"bunched":{"first_bucket":23,"last_bucket":23,"members":98,"pct":98,"from":"16:55","to":"16:58"}}
  ```
- **`variation`** — per-token-type distinct counts and sample values. This is the key field for triage: agents can answer "which IPs?", "how many distinct UUIDs?", "which namespaces?" from a single invocation. Hostnames appear under their own `FQDN` key since 0.4.4 (older versions mislabeled them `IPV4`). A syslog/journal line's positional host — `<TIMESTAMP> gw-core dnsmasq[<PID>]:` — folds to `<HOST>` and appears under its own `HOST` key, so the same event from several devices is one group.
- **`samples`** — up to 7 values, deterministic (same input = same samples across runs). Empty for count-only types (TIMESTAMP, NUMBER, DURATION, PORT, PID, KEY_VALUE). `samples_complete` says whether the list is every distinct value, and `omitted_sample_values` how many are not listed.
- **`VARIES`** — where a group's members disagree in something no detector tokenised (`Unreachable` vs `Timeout`, `Busy` vs `Reject`, a bare word vs a placeholder); the group's `normalized` shows `<VARIES>` there, keeping a shared field name in front (`msg=<VARIES>`) and treating a quoted value with spaces as one slot. Its `samples` are ordered by `sample_counts` (most frequent first, the rarest last), so a 1-in-7,000 outcome is visible without reading the raw lines; `∅` counts members that lack the word. Text mode shows the same as `varies×N {word×count, …}`. The entry pools every slot of the template; when `normalized` holds two or more `<VARIES>`, `VARIES.slots` carries one entry per slot in template order (`slots[0]` is the first `<VARIES>`), with the same fields, its own cap and its own `samples_complete` — read `slots` to know which slot a value filled. A line that differs from a group's founder in two or more sentence words (verb and outcome) founds its own group instead.
- **`capped: true`** — distinct_count is a lower bound (`distinct_count_kind: "lower_bound"`; otherwise `"exact"`). A retained group can also exceed the 64 distinct unequal-length shapes kept for final word alignment; its `VARIES` then has a zero lower bound and empty samples/counts rather than misleading partial counts. The group's occurrence count and other token rollups remain available.
- **`normalized`** — the template with `<TOKEN>` placeholders; this is what lessence groups by.
- **What stays literal** — a placeholder replaces a value, never a field's name or a log level, and fields that identify the event (call site, program, option name, status class, unit, route) stay on the line: two templates that differ in such a word are two different events. Per-shape rules: references/flags.md, "Reading a template".

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

### journalctl (a unit, a boot, a time window)
```bash
journalctl -u nginx --since "2 hours ago" | lessence --summary -q
# The same event from several hosts is one group; the hosts are in the HOST facts:
journalctl --since today | lessence --format json \
  | jq -r 'select(.type=="group" and .variation.HOST) | "\(.count)\t\(.variation.HOST.samples|join(","))\t\(.normalized[:80])"'
```

### Test failures (a long test run, a few failing cases)
```bash
# Passing tests fold away; each failure and its stack trace stays as one event
cargo test 2>&1 | lessence --no-report -q --frame-continuations
```
Unfolded lines are the failures: read those, not the counts.

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
# Exit code 1 if pattern found, 0 if clean — also behind `| head`: a closed
# pipe never turns a failure into exit 0
```

## Common Mistakes

- **"Compression too aggressive"** — high compression means few distinct patterns. Check `--stats-json` for exact counts.
- **"Error didn't appear"** — `--top N` shows the N **most frequent** patterns, which in noisy logs are often the harmless ones; a one-off error gets excluded. `--top` is for dominant behavior (crash loops, capacity); for needle-in-haystack use plain `lessence -q | grep -i error`.
- **"`ipv4×40` — forty different clients?"** — not necessarily. lessence groups by pattern, not by value. Varying IPs may be the same source.
- **"--essence had no effect"** — only helps when timestamps are the sole differentiator between lines.
- **"Short lines dominate --top"** — JSON fragments like `],` or `}` are high-frequency noise. Filter with `grep -v '^.\{0,10\}$'` first, or increase N.

## Reference

- **`references/flags.md`** — Complete flag reference including security limits
  (`--sanitize`, `--sanitize-pii`, `--max-line-length`, `--max-lines`), pattern control
  (`--threshold`, `--min-collapse`, `--disable-patterns`), and CI integration
  (`--fail-on-pattern`). Consult when needing a flag beyond the core set above.
- **Repo only, not printed by `--skill`** — `references/sources.md` (what each
  claim here was verified against; consult when one looks stale),
  `references/trigger-evals.json` and `references/choice-evals/` (eval sets for
  when this skill fires and whether it is chosen over tail/grep), and
  `docs/format-json-schema.md` (every JSON field).
