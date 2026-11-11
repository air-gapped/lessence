# lessence — Complete Flag Reference

Sections: Analysis Modes · Output Control · The saved report · Pattern Control · Security and Limits · Record framing · Diagnosing the fold · Reading a template · CI Integration (exit codes) · Performance · Other · Every flag, from the binary.

## Analysis Modes

| Flag | Description |
|------|-------------|
| `--fit` / `--human` | One screen overview that stays visible after the command returns. Adapts to terminal height — no scrolling. Implies `--summary`. |
| `--summary` | One-line-per-pattern frequency overview. Shows original representative lines, not normalized tokens. Combine with `--top N` for compact output. |
| `--preflight` | JSON to stdout for automation/CI: the briefing (line count, levels, time span and histogram, templates, token counts) plus run metadata (version, schema_version, source, input_hash, format, degraded). Prints nothing else, so `--top`, `--summary`, `--fit`, `--explain` and `--stats-json` with it are a usage error (exit 2) naming the flag; `-q` is accepted. |

Start with `--fit` to see what's going on at a glance. Use `--summary --top 15`
for a specific count, or drill into specific patterns with default mode.

## Output Control

| Flag | Default | Description |
|------|---------|-------------|
| `--format text\|markdown\|json` | `text` | Output format. `json` emits JSONL with per-group rollup metadata (best for agents — see SKILL.md). Markdown adds headers and code blocks for reports. |
| `-q` / `--quiet` | off | Suppress statistics footer. Alias: `--no-stats`. |
| `--stats-json` | off | Emit JSON statistics to stderr instead of the human-readable footer (which also goes to stderr since 0.4.4 — stdout carries only log output). The default run, `--summary` and `--top N` report the same `input_lines` (every physical line, continuations included); `output_lines` is what that mode printed. `compression_ratio` is the same for the default run and `--summary`; under `--top N` it covers only the N groups shown, so take the ratio from a run without `--top`. |
| `--top N` | off | Show only the N most frequent patterns, sorted by count descending. `--top 0` shows all patterns, in every mode. |

## The saved report (default runs)

A default run (`lessence app.log`, no `--format` and none of `--summary`,
`--top`, `--fit`, `--preflight`, `--explain`) writes the **complete** folded
JSON of the run — the same schema-1 records `--format json` emits — to a file,
and prints a **bounded overview** of that file on stdout. The report holds
every group; stdout is a view that declares everything it leaves out.

| Flag | Default | Description |
|------|---------|-------------|
| `--report-dir DIR` | `$LESSENCE_REPORT_DIR`, else `$XDG_STATE_HOME/lessence/reports`, else `~/.local/state/lessence/reports` | Where the run directory `run-<UTC date>-<8 hex>` is created (0700, report file 0600). Never the working directory. |
| `--report-max-bytes N` | `1G` | Per-run cap on the report file. K/M/G suffixes. Nothing bounds accumulated disk use; **the directory grows until you delete it**. |
| `--no-report` | off | Write no report: stream the folded text to stdout and the briefing to stderr, exactly as before this feature. Accepted in every other mode too, where it does nothing: they write no report already. |
| `--overview N\|all` | `40` | Groups in the stdout overview. `0` prints none; `all` prints every group in report order with no byte budget and no preview cuts. Max 10000. |
| `--overview-bytes B` | `16384` | Byte budget for the whole overview — briefing, locators, entries and recipes together. Usage error with `--overview all`. |

The four that shape a report (`--report-dir`, `--report-max-bytes`,
`--overview`, `--overview-bytes`) apply to the default run only; with any
other mode they are a usage error, never silently ignored, and the error names
what to run instead. `--no-report` is accepted everywhere: no other mode
writes a report, so there it does nothing.
`LESSENCE_REPORT_DIR` is read only there too. **There is no report in
`--format json`:** that mode streams every group to stdout already, so
`--format json --overview all` is a usage error and plain `--format json` is
the command that was meant.

**Use `--no-report` for `tail -f` and any live source.** The report needs input
EOF to write its summary record; a source that never ends never gets a report
or an overview.

How to read the overview:

1. The **head locator** follows the briefing (first line under `-q`) and the
   **tail locator** follows the last entry, above the jq recipes, so
   a truncated capture keeps one of them. It names the report path, whether the
   file is complete, whether the input was complete or `degraded(<codes>)`, the
   run id, the report size, and `<total> total, <selected> selected, <printed>
   printed, <omitted> omitted`. `printed < selected` means the byte budget cut
   the rest off; the report still has them.
2. The **entries** are the rarest half and the most frequent half of the
   selection, shown by ascending group id. A template over 1024 bytes and
   samples over 80 bytes are previewed, and the entry says `previewed here:
   template, samples` when this screen cut anything.
3. **Two different omissions, never conflated.** `previewed here` is what the
   screen cut; `report-sampled` on the `variation:` line is what the *report*
   itself does not hold, because the rollup hit its cap. The count kind is on
   the line too: `ip=9` is exact, `ip>=64` is a lower bound, `ip~9 (kind
   unstated)` means the record did not say. A group whose entry reads
   `variation: not recorded` had no rollup computed, or nothing to vary — the
   record does not distinguish those, and neither does the overview.
4. The **recipes** at the end are jq one-liners against the report by group
   id — none of them prints the whole file, the two listing ones stop at 40
   rows and say so, and the path is shell-quoted. Reach for those instead of
   `cat`.

The report directory is never pruned. Delete old `run-*` directories yourself.

## Pattern Control

| Flag | Default | Description |
|------|---------|-------------|
| `--essence` | off | Strip timestamps before normalization. Lines differing only by time merge. Useful for comparing log structure across time periods. |
| `--threshold N` | 83 | Similarity percentage (0-100) required to group lines — since 0.4.4, the share of whitespace tokens two normalized lines have in common (longest common subsequence, so an inserted token no longer breaks grouping). Lower (e.g. 75) = more aggressive grouping but re-merges distinct HTTP status classes and boolean states; raise toward 88-92 only when per-message splitting matters more than fold cost (~2x output and time on diverse corpora). |
| `--min-collapse N` | 3 | Minimum lines in a group before folding. 3 is also the floor — the binary rejects lower values. |
| `--disable-patterns X,Y` | none | Comma-separated list of pattern detectors to skip. It also reaches values inside quoted strings. A detector that finds an entity `--sanitize` names stays on: `email` keeps `email`, `ip` keeps the address part of `network`, `host` keeps the host part of `network` and `timestamp` (a syslog host is placed by the timestamp before it). |

### Valid pattern names for `--disable-patterns`

`timestamp`, `hash`, `network`, `uuid`, `email`, `path`, `duration`,
`json`, `kubernetes`, `http-status`, `brackets`, `key-value`, `process`,
`quoted-string`, `name`

Example: `--disable-patterns timestamp,uuid` to keep timestamps and UUIDs literal.

## Security and Limits

| Flag | Default | Description |
|------|---------|-------------|
| `--sanitize ENTITY[:ACTION]` | off | Mask one entity: `email`, `credential`, `host` or `ip`. Action `redact` (default) gives the class tag (`<HOST>`); `pseudonym` gives a keyed tag (`<HOST:1a2b3c4d5e6f7a8b>`, HMAC-SHA256 under a 256-bit per-run key, truncated to 64 bits) that is the same for the same value within a run, so a masked host still folds with itself and the rollup still counts distinct hosts. The key is drawn per run; to correlate hosts across two runs, set `LESSENCE_SANITIZE_KEY` to the same value for both. Repeatable or comma-separated (`--sanitize host,ip:pseudonym`). Masks the shown lines, the template, every rollup sample and the `--explain` `first_diff` words. |
| `--sanitize-pii` | off | Exactly `--sanitize email,credential`, never widened. Mask emails (`<EMAIL>`) and credential-class values: `key=value`/`key: value` assignments to credential-named keys (`<SECRET>`), JWTs (`<JWT>`), and `sk-`/`ghp_`/`xox`-style provider keys (`<KEY>`). `credential` also masks the credentials of an `Authorization` header or `Bearer` token and the password in a URL userinfo (`<SECRET>`). |
| `--max-line-length N` | 1MB | Skip lines exceeding this length. Supports K/M/G suffixes. |
| `--max-lines N` | unlimited | Stop processing after N lines. |
| `--preserve-color` | off | Keep ANSI escape codes (stripped by default). |

## Record framing

| Flag | Default | Description |
|------|---------|-------------|
| `--frame-continuations` | off | Attach indented lines to the record above them, so a stack trace folds as one event instead of one group per frame. |

Reach for it when a log carries multi-line records — Python/Java tracebacks,
`Caused by:` chains, indented YAML — and the fold has split one exception into
a group per frame, which destroys the causal order. Off by default because it
changes what a record means: one output record can then span several physical
lines. Line numbers still point at the line the record starts on, the stats
footer still counts physical lines, and `--fail-on-pattern` still tests every
physical line, so a match hiding inside a frame still fails the run.

## Diagnosing the fold

| Flag | Default | Description |
|------|---------|-------------|
| `--explain` | off | Annotate each JSON group record with `nearest`: `group_line_no` (the `first.line_no` of the existing group this line scored highest against before founding its own), the `score` (percent), `anchor_mismatch: true` when an exact-match field kept them apart whatever the score, and `first_diff` — `{ours, theirs, at}`, the first whitespace token where the two disagree and its position. Implies `--format json`. |

Reach for it when a log folds worse than expected and the question is *why
these lines did not join*. A singleton whose `nearest.score` sits just under
`--threshold` with `first_diff` on a bare number, name, or quoted value is a
shape lessence does not yet recognise:

```bash
lessence --explain app.log | jq -c 'select(.count==1 and .nearest.score>70) | {n:.first.line_no, score:.nearest.score, diff:.nearest.first_diff}'
```

Groups that joined an existing group, or were founded into an empty buffer,
carry no `nearest`. The field is only computed under the flag and never
influences the fold; with the flag off, output is byte-identical.

| Flag | Default | Description |
|------|---------|-------------|
| `--diff LESSENCE` | — | Run `LESSENCE` (another lessence binary) on the same input and print only the groups that fold differently: `joined` (used to stand alone, now folds into another), `split` (the reverse), `resized` (same group, different membership). Ends with `groups: A -> B   moved: N`. Exit 1 if anything moved, like `diff(1)`; exit 2 if the comparison itself failed. Needs a FILE argument (not stdin) and takes no fold flags (`--threshold`, `--min-collapse`, `--disable-patterns`, `--frame-continuations`, `--essence`). |

Reach for it after any change to `src/normalize.rs` or `src/folder/`, with the
previous release binary as the argument. It replaces running two binaries by
hand and diffing hundreds of output lines: each reported line is one *input*
line whose fate changed, ready to be judged.

```bash
lessence --diff ~/.cargo/bin/lessence examples/originals/*.log
```

Both sides run with `--format json --threads 1 -q`; groups are matched on
`first.line_no`, so the report is stable across builds even though JSON `id`
is assigned in flush order.

## Reading a template

What each placeholder covers and what stays literal, by shape. Consult when a
template shows a placeholder or a literal word whose scope is unclear.

- **PCI devices** — exact PCI addresses such as `0000:21:00.0` stay visible because different addresses already keep hardware events apart. An address inside a normalized route is shown beside that route skeleton. An address embedded in a path stays visible when the surrounding path text varies.
- **Systemd unit subjects** — the template shows the unit identity: `modprobe@loop.service` and `modprobe@fuse.service` remain distinct; numeric instances show `<N>` and opaque hex/UUID runs show `<ID>`. Exact instance names remain in the `NAME` facts. Different instances of the same unit kind can still fold together. This applies when the unit is the subject immediately after `systemd[PID]:`, not to messages about starting a unit or to mount/device units.
- **CPU quantities** — a `cpu` field with a millicpu value such as `750m` becomes `<CPU_QUANTITY>`, with exact values in `CPU_QUANTITY` samples and a separate `cpu_quantities` count. Plain, JSON and escaped configuration fields are supported. A neighboring `timeout=20m` is not read as CPU (it shows as `timeout=<KEY_VALUE>`); unitless CPU IDs are not interpreted as millicpu.
- **Decimal measurements** — long fractional digits stay part of the decimal, even when their length resembles an epoch timestamp. `<DECIMAL>` represents the whole measurement; valid epoch timestamps still normalize as timestamps.
- **HTTP requests** — when methods vary within a group, the quoted request keeps its route visible: `"<VARIES> /route HTTP/<DECIMAL>"`. The `VARIES` facts count methods such as `GET` and `POST`, rather than hiding the whole request. Protocol-version variation has its own slot. Prose requests such as `making POST http request: http://host/promote` and `GET https://host/items/42` keep method and route separate: `http://<HOST>/promote` or `https://<HOST>/items/<N>`. Hosts, object IDs and queries may vary; complete targets remain in `PATH` facts.
- **Field names and levels** — a placeholder replaces a field's value, never its name: `timeout=<KEY_VALUE>` and `port=<KEY_VALUE>` are different settings, `podStartSLOduration=<DURATION_FIELD>` and `imagePullDuration=<DURATION_FIELD>` different measurements, each in its own group. A generated name keeps its component and folds only the generated tail: `nginx-<SUFFIX>` and `redis-<SUFFIX>`, not one `<COMPONENT>-<SUFFIX>`. A log level is never a placeholder — `[error]`, `[NOTICE]` and `level=error` stay literal, so an error and an info line that otherwise read alike are two groups. A run of two or more context brackets beside a level still folds (`[error] [main] [proxy-7]` → `[error] <BRACKET_CONTEXT> upstream gone`); a single varying bracket shows as `[<VARIES>]`.
- **Kubernetes Event objects** — only the event's `ObjectMeta:{…}` folds to `<EVENT_OBJECT>`; its `Reason:`, `Type:` and involved object stay on the line.
- **Event identity** — anchored call sites, Python traceback frames (file, line, function), and program fields such as `exe=` or `"binary":` stay literal in the template. They already keep different events apart; showing them makes the reason visible. Other file paths still normalize to `<PATH>`.
- **Audit syscall outcomes** — raw `type=SYSCALL msg=audit(...)` records keep `success=yes` and `success=no` in separate groups, with the outcome visible in the template. Repeated events with the same outcome can still fold across return values.
- **CLI options** — recognized long and single-letter option names in logged commands stay visible and keep different options in separate groups. Their values may vary, including inside quoted commands. Option names no longer appear as `PATH` samples. Repeated commands can still fold across revision hashes and execution IDs; single-dash words such as `-sdown` remain prose.
- **Status classes** — anchored JSON/logfmt status fields stay visible as `<STATUS_2XX>`, `<STATUS_4XX>`, and so on; their exact numeric codes remain in the numeric rollup. Quoted HTTP responses use `<HTTP_STATUS_2XX>`. Codes within one class (such as 200 and 204) can fold together; different classes stay separate. These class identities stay visible when token detection is disabled. A generic status field can also be a process exit code, so its marker does not label it as HTTP.

## Reading a group's time range

A group's first and last timestamp are shown as the log wrote them. Its
spread between them is in the JSON `time_range.buckets`: member counts per
bucket on the briefing histogram's grid (same `bucket_seconds`, same
indices), present when 3 or more members carry a timestamp in more than one
bucket. Lines without a parseable timestamp are not counted. A group is
**bunched** when it has at least 10 timestamped members over at least 4
buckets of its own span, and the shortest run of buckets holding 90% of them
covers at most a quarter of that span, both in buckets and in the seconds
between the run's first and last member. A bunched group's marker, in the
folded text and in the overview, names the run:

```
[+98 similar | 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55–16:58 | ipv4×4]
[100x] id=0 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55–16:58
```

The percentage is rounded down. The times are clock times when every member
falls on one date, and carry the date otherwise (the year only when the log's
stamps state one). The rule is fixed; no flag changes it.

## CI Integration

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on-pattern REGEX` | none | Exit code 1 if any input line matches the regex. Exit code 2 if regex is invalid. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (also when output pipe closes early, e.g. `\| head`) |
| 1 | `--fail-on-pattern` matched, or a named input file could not be opened (remaining files are still processed, like cat/grep). A closed output pipe never turns this into 0, in any mode: with `--fail-on-pattern`, lessence reads on to the end of the input for the verdict |
| 2 | Invalid `--fail-on-pattern` regex, or a usage error: a flag the chosen mode would ignore is refused by name, never dropped silently |

## Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--threads N` | auto | Number of threads. Use `--threads 1` for deterministic single-threaded mode. |

## Other

| Flag | Description |
|------|-------------|
| `--completions SHELL` | Generate shell completions (bash/zsh/fish/elvish/powershell) and exit. |
| `--help-human` | Short help for a person and exit; `--help` itself is written for agents and opens with the agent block (skip-if-present, `--skill`, the JSON surface). Exits before any input is opened. |
| `--skill [TOPIC]` | Print the bundled agent skill and exit: `skill` (SKILL.md, the default) or `flags` (this file). The text is embedded at build time, so it is exactly the skill verified for the binary that prints it. Exits before any input is opened; an unknown topic exits 2. |
| `--json` | Same as `--format json`. Conflicts with an explicit `--format` and, like every output-mode flag, with `--distill`. |
| `FILE...` | Input files. Reads stdin if none given. Use `-` for explicit stdin. |

## Every flag, from the binary

Generated from the binary's own argument parser (`make docs`); the hand-written
sections above explain, this block is the authoritative list.

<!-- gen:flags:begin -->
```
--skill [TOPIC]    Print the bundled agent skill and exit: `skill` (SKILL.md, the default) or `flags` (the complete flag reference). Install with `lessence --skill > ~/.claude/skills/lessence/SKILL.md` and `lessence --skill flags > ~/.claude/skills/lessence/references/flags.md`
--format <FORMAT>    Output format: text (default), markdown, json (JSONL for agent consumption) [default: text]
--json    Same as --format json [default: false]
--preflight    JSON analysis report to stdout (for automation/CI) [default: false]
--explain    Dev mode: annotate each JSON group record with the existing group it scored highest against before founding its own, the score, and the first token that differed. Implies --format json [default: false]
--stats-json    Emit JSON statistics to stderr (replaces human-readable stats) [default: false]
--threshold <THRESHOLD>    Percent of tokens two lines must share to group (0-100). Lower (e.g. 75) for more folding; raise for stricter, per-message splitting [default: 83]
--min-collapse <MIN_COLLAPSE>    Minimum lines before folding (min: 3) [default: 3]
--disable-patterns <DISABLE_PATTERNS>    Disable specific pattern groups (comma-separated). Valid names: timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name
--frame-continuations    Attach indented continuation lines to the record above them, so a stack trace folds as one event instead of one group per frame [default: false]
--essence    Enable essence mode (timestamp removal/tokenization for temporal independence) [default: false]
--quiet (alias: --no-stats) (-q)    Disable statistics output (enabled by default) [default: false]
--summary    One-line-per-pattern frequency summary (use with --top N for compact overview) [default: false]
--top <TOP>    Show only the N most frequent patterns, sorted by count (0 for all)
--fit (alias: --human)    Quick human-readable overview that fits your screen — no scrolling [default: false]
--preserve-color    Preserve ANSI color codes (stripped by default) [default: false]
--report-dir <DIR>    Where the default run saves its report (default: $LESSENCE_REPORT_DIR, else $XDG_STATE_HOME/lessence/reports, else ~/.local/state/lessence/reports). A fresh run-YYYYmmdd-HHMMSS-8hex directory per run; the directory grows until you delete it (default text run only)
--report-max-bytes <N>    Per-run cap on the report file (default 1G, supports K/M/G). Nothing bounds accumulated disk use across runs (default text run only)
--no-report    Do not save a report: stream today's folded text to stdout and the briefing to stderr. Use this for `tail -f` and any live source — a source that never reaches EOF never gets a report. Every other mode writes no report already; there it does nothing [default: false]
--overview <N|all>    Groups to show in the stdout overview: N (default 40, max 10000), 0 for none, or `all` for every group with no byte budget (default text run only)
--overview-bytes <B>    Byte budget for the whole stdout overview (default 16384) (default text run only)
--sanitize-pii    Enable PII sanitization (mask email addresses and sensitive data, default: disabled) [default: false]
--sanitize <ENTITY[:ACTION]>    Mask an entity: email, credential, host or ip, optionally with an action — redact (default) or pseudonym (a keyed tag such as <HOST:1a2b3c4d5e6f7a8b>, the same for the same value within a run, so masked hosts still fold; set LESSENCE_SANITIZE_KEY to make tags comparable across runs). Repeatable or comma-separated; --sanitize-pii equals --sanitize email,credential
--max-line-length <MAX_LINE_LENGTH>    Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
--max-lines <MAX_LINES>    Maximum number of lines to process (stop after this count, default: no limit)
--fail-on-pattern <FAIL_ON_PATTERN>    Exit 1 if any input line matches this regex (for CI gating)
--threads <THREADS>    Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
--diff <LESSENCE>    Dev mode: run this other lessence binary on the same input and print only the groups that fold differently. Exit 1 if anything moved, 2 on error. Needs a FILE argument and takes no fold flags
--completions <COMPLETIONS>    Generate shell completion script and exit
--help-human    Short help for people and exit (this --help is written for agents) [default: false]
FILE...    Input files (reads stdin if none given, use - for explicit stdin)
```
<!-- gen:flags:end -->
