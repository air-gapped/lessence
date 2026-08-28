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
| `--sanitize-pii` | off | Mask emails (`<EMAIL>`) and credential-class values: `key=value`/`key: value` assignments to credential-named keys (`<SECRET>`), JWTs (`<JWT>`), and `sk-`/`ghp_`/`xox`-style provider keys (`<KEY>`). |
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
| `FILE...` | Input files. Reads stdin if none given. Use `-` for explicit stdin. |
