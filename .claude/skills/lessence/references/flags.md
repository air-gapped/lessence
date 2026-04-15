# lessence — Complete Flag Reference

## Analysis Modes

| Flag | Description |
|------|-------------|
| `--fit` / `--human` | One screen overview that stays visible after the command returns. Adapts to your terminal height — no scrolling. Implies `--summary`. |
| `--summary` | One-line-per-pattern frequency overview. Shows original representative lines, not normalized tokens. Combine with `--top N` for compact output. |
| `--preflight` | JSON analysis report to stdout for automation/CI. Shows compression ratio, pattern counts, recommendations. |

Start with `--fit` to see what's going on at a glance. Use `--summary --top 15`
for a specific count, or drill into specific patterns with default mode.

## Output Control

| Flag | Default | Description |
|------|---------|-------------|
| `--format text\|markdown` | `text` | Output format. Markdown adds headers and code blocks for reports. |
| `-q` / `--quiet` | off | Suppress statistics footer. Alias: `--no-stats`. |
| `--stats-json` | off | Emit JSON statistics to stderr instead of human-readable footer. |
| `--top N` | off | Show only the N most frequent patterns, sorted by count descending. |

## Pattern Control

| Flag | Default | Description |
|------|---------|-------------|
| `--essence` | off | Strip timestamps before normalization. Lines differing only by time merge. Useful for comparing log structure across time periods. |
| `--threshold N` | 75 | Similarity percentage (0-100) required to group lines. Lower = more aggressive grouping. |
| `--min-collapse N` | 3 | Minimum lines in a group before folding. Set to 2 for maximum compression. |
| `--disable-patterns X,Y` | none | Comma-separated list of pattern detectors to skip. |

### Valid pattern names for `--disable-patterns`

`timestamp`, `hash`, `network`, `uuid`, `email`, `path`, `duration`,
`json`, `kubernetes`, `http-status`, `brackets`, `key-value`, `process`,
`quoted-string`, `name`

Example: `--disable-patterns timestamp,uuid` to keep timestamps and UUIDs literal.

## Security and Limits

| Flag | Default | Description |
|------|---------|-------------|
| `--sanitize-pii` | off | Mask email addresses with `<EMAIL>` in output. |
| `--max-line-length N` | 1MB | Skip lines exceeding this length. Supports K/M/G suffixes. |
| `--max-lines N` | unlimited | Stop processing after N lines. |
| `--preserve-color` | off | Keep ANSI escape codes (stripped by default). |

## CI Integration

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on-pattern REGEX` | none | Exit code 1 if any input line matches the regex. Exit code 2 if regex is invalid. |

## Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--threads N` | auto | Number of threads. Use `--threads 1` for deterministic single-threaded mode. |

## Other

| Flag | Description |
|------|-------------|
| `--completions SHELL` | Generate shell completions (bash/zsh/fish/elvish/powershell) and exit. |
| `FILE...` | Input files. Reads stdin if none given. Use `-` for explicit stdin. |
