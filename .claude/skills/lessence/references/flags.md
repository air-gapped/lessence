# lessence — Complete Flag Reference

## Analysis Modes

| Flag | Description |
|------|-------------|
| `--fit` / `--human` | One screen overview that stays visible after the command returns. Adapts to terminal height — no scrolling. Implies `--summary`. |
| `--summary` | One-line-per-pattern frequency overview. Shows original representative lines, not normalized tokens. Combine with `--top N` for compact output. |
| `--preflight` | JSON analysis report to stdout for automation/CI. Shows compression ratio, pattern counts, recommendations. |

Start with `--fit` to see what's going on at a glance. Use `--summary --top 15`
for a specific count, or drill into specific patterns with default mode.

## Output Control

| Flag | Default | Description |
|------|---------|-------------|
| `--format text\|markdown\|json` | `text` | Output format. `json` emits JSONL with per-group rollup metadata (best for agents — see SKILL.md). Markdown adds headers and code blocks for reports. |
| `-q` / `--quiet` | off | Suppress statistics footer. Alias: `--no-stats`. |
| `--stats-json` | off | Emit JSON statistics to stderr instead of the human-readable footer (which also goes to stderr since 0.4.4 — stdout carries only log output). |
| `--top N` | off | Show only the N most frequent patterns, sorted by count descending. |

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
| `--no-report` | off | Write no report: stream the folded text to stdout and the briefing to stderr, exactly as before this feature. |
| `--overview N\|all` | `40` | Groups in the stdout overview. `0` prints none; `all` prints every group in report order with no byte budget and no preview cuts. Max 10000. |
| `--overview-bytes B` | `16384` | Byte budget for the whole overview — briefing, locators, entries and recipes together. Usage error with `--overview all`. |

All five apply to the default run only; with any other mode they are a usage
error, never silently ignored, and the error names what to run instead.
`LESSENCE_REPORT_DIR` is read only there too. **There is no report in
`--format json`:** that mode streams every group to stdout already, so
`--format json --overview all` is a usage error and plain `--format json` is
the command that was meant.

**Use `--no-report` for `tail -f` and any live source.** The report needs input
EOF to write its summary record; a source that never ends never gets a report
or an overview.

How to read the overview:

1. The **head locator** is the first line and the **tail locator** the last, so
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
| `--disable-patterns X,Y` | none | Comma-separated list of pattern detectors to skip. |

### Valid pattern names for `--disable-patterns`

`timestamp`, `hash`, `network`, `uuid`, `email`, `path`, `duration`,
`json`, `kubernetes`, `http-status`, `brackets`, `key-value`, `process`,
`quoted-string`, `name`

Example: `--disable-patterns timestamp,uuid` to keep timestamps and UUIDs literal.

## Security and Limits

| Flag | Default | Description |
|------|---------|-------------|
| `--sanitize ENTITY[:ACTION]` | off | Mask one entity: `email`, `credential`, `host` or `ip`. Action `redact` (default) gives the class tag (`<HOST>`); `pseudonym` gives a keyed tag (`<HOST:1a2b3c4d5e6f7a8b>`, HMAC-SHA256 under a 256-bit per-run key, truncated to 64 bits) that is the same for the same value within a run, so a masked host still folds with itself and the rollup still counts distinct hosts. The key is drawn per run; to correlate hosts across two runs, set `LESSENCE_SANITIZE_KEY` to the same value for both. Repeatable or comma-separated (`--sanitize host,ip:pseudonym`). Masks the shown lines, the template and every rollup sample. |
| `--sanitize-pii` | off | Exactly `--sanitize email,credential`, never widened. Mask emails (`<EMAIL>`) and credential-class values: `key=value`/`key: value` assignments to credential-named keys (`<SECRET>`), JWTs (`<JWT>`), and `sk-`/`ghp_`/`xox`-style provider keys (`<KEY>`). |
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
| `--explain` | off | Annotate each JSON group record with `nearest`: the `first.line_no` of the existing group this line scored highest against before founding its own, the `score` (percent), and `first_diff` — the first whitespace token where the two disagree. Implies `--format json`. |

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
| `--diff LESSENCE` | — | Run `LESSENCE` (another lessence binary) on the same input and print only the groups that fold differently: `joined` (used to stand alone, now folds into another), `split` (the reverse), `resized` (same group, different membership). Ends with `groups: A -> B   moved: N`. Exit 1 if anything moved, like `diff(1)`. |

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

## CI Integration

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on-pattern REGEX` | none | Exit code 1 if any input line matches the regex. Exit code 2 if regex is invalid. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (also when output pipe closes early, e.g. `\| head`) |
| 1 | `--fail-on-pattern` matched, or a named input file could not be opened (remaining files are still processed, like cat/grep) |
| 2 | Invalid `--fail-on-pattern` regex |

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
--top <TOP>    Show only the N most frequent patterns, sorted by count
--fit (alias: --human)    Quick human-readable overview that fits your screen — no scrolling [default: false]
--preserve-color    Preserve ANSI color codes (stripped by default) [default: false]
--report-dir <DIR>    Where the default run saves its report (default: $LESSENCE_REPORT_DIR, else $XDG_STATE_HOME/lessence/reports, else ~/.local/state/lessence/reports). A fresh run-YYYYmmdd-HHMMSS-8hex directory per run; the directory grows until you delete it (default text run only)
--report-max-bytes <N>    Per-run cap on the report file (default 1G, supports K/M/G). Nothing bounds accumulated disk use across runs (default text run only)
--no-report    Do not save a report: stream today's folded text to stdout and the briefing to stderr. Use this for `tail -f` and any live source — a source that never reaches EOF never gets a report (default text run only) [default: false]
--overview <N|all>    Groups to show in the stdout overview: N (default 40, max 10000), 0 for none, or `all` for every group with no byte budget (default text run only)
--overview-bytes <B>    Byte budget for the whole stdout overview (default 16384) (default text run only)
--sanitize-pii    Enable PII sanitization (mask email addresses and sensitive data, default: disabled) [default: false]
--sanitize <ENTITY[:ACTION]>    Mask an entity: email, credential, host or ip, optionally with an action — redact (default) or pseudonym (a keyed tag such as <HOST:1a2b3c4d5e6f7a8b>, the same for the same value within a run, so masked hosts still fold; set LESSENCE_SANITIZE_KEY to make tags comparable across runs). Repeatable or comma-separated; --sanitize-pii equals --sanitize email,credential
--max-line-length <MAX_LINE_LENGTH>    Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
--max-lines <MAX_LINES>    Maximum number of lines to process (stop after this count, default: no limit)
--fail-on-pattern <FAIL_ON_PATTERN>    Exit 1 if any input line matches this regex (for CI gating)
--threads <THREADS>    Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
--diff <LESSENCE>    Dev mode: run this other lessence binary on the same input and print only the groups that fold differently. Exit 1 if anything moved
--completions <COMPLETIONS>    Generate shell completion script and exit
--help-human    Short help for people and exit (this --help is written for agents) [default: false]
FILE...    Input files (reads stdin if none given, use - for explicit stdin)
```
<!-- gen:flags:end -->
