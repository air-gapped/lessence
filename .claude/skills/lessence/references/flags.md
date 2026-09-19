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
| `--skill [TOPIC]` | Print the bundled agent skill and exit: `skill` (SKILL.md, the default) or `flags` (this file). The text is embedded at build time, so it is exactly the skill verified for the binary that prints it. Exits before any input is opened; an unknown topic exits 2. |
| `--json` | Same as `--format json`. Conflicts with an explicit `--format` and, like every output-mode flag, with `--distill`. |
| `FILE...` | Input files. Reads stdin if none given. Use `-` for explicit stdin. |

## Every flag, from the binary

Generated from the binary's own argument parser (`make docs`); the hand-written
sections above explain, this block is the authoritative list.

<!-- gen:flags:begin -->
```
--threshold <THRESHOLD>    Percent of tokens two lines must share to group (0-100). Lower (e.g. 75) for more folding; raise for stricter, per-message splitting [default: 83]
--min-collapse <MIN_COLLAPSE>    Minimum lines before folding (min: 3) [default: 3]
--disable-patterns <DISABLE_PATTERNS>    Disable specific pattern groups (comma-separated). Valid names: timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name
--quiet (alias: --no-stats) (-q)    Disable statistics output (enabled by default) [default: false]
--preserve-color    Preserve ANSI color codes (stripped by default) [default: false]
--summary    One-line-per-pattern frequency summary (use with --top N for compact overview) [default: false]
--preflight    JSON analysis report to stdout (for automation/CI) [default: false]
--format <FORMAT>    Output format: text (default), markdown, json (JSONL for agent consumption) [default: text]
--json    Same as --format json [default: false]
--essence    Enable essence mode (timestamp removal/tokenization for temporal independence) [default: false]
--threads <THREADS>    Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
--sanitize-pii    Enable PII sanitization (mask email addresses and sensitive data, default: disabled) [default: false]
--sanitize <ENTITY[:ACTION]>    Mask an entity: email, credential, host or ip, optionally with an action — redact (default) or pseudonym (a keyed tag such as <HOST:1a2b3c4d5e6f7a8b>, the same for the same value within a run, so masked hosts still fold; set LESSENCE_SANITIZE_KEY to make tags comparable across runs). Repeatable or comma-separated; --sanitize-pii equals --sanitize email,credential
--max-line-length <MAX_LINE_LENGTH>    Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
--max-lines <MAX_LINES>    Maximum number of lines to process (stop after this count, default: no limit)
--stats-json    Emit JSON statistics to stderr (replaces human-readable stats) [default: false]
--top <TOP>    Show only the N most frequent patterns, sorted by count
--fit (alias: --human)    Quick human-readable overview that fits your screen — no scrolling [default: false]
--fail-on-pattern <FAIL_ON_PATTERN>    Exit 1 if any input line matches this regex (for CI gating)
--frame-continuations    Attach indented continuation lines to the record above them, so a stack trace folds as one event instead of one group per frame [default: false]
--explain    Dev mode: annotate each JSON group record with the existing group it scored highest against before founding its own, the score, and the first token that differed. Implies --format json [default: false]
--diff <LESSENCE>    Dev mode: run this other lessence binary on the same input and print only the groups that fold differently. Exit 1 if anything moved
--completions <COMPLETIONS>    Generate shell completion script and exit
--skill <TOPIC>    Print the bundled agent skill and exit: `skill` (SKILL.md, the default) or `flags` (the complete flag reference). Install with `lessence --skill > ~/.claude/skills/lessence/SKILL.md` and `lessence --skill flags > ~/.claude/skills/lessence/references/flags.md`
FILE...    Input files (reads stdin if none given, use - for explicit stdin)
```
<!-- gen:flags:end -->
