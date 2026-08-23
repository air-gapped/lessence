# lessence — extract the essence of your logs

Your pod is crash-looping. `kubectl logs` dumps 70,000 lines. What's actually broken?

<!-- gen:example:begin -->
```
$ lessence kubelet.log

E0909 13:07:09.181236    3116 nestedpendingoperations.go:348] Operation for "{volumeName:kubernetes.io/projected/9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc-kube-api-access-52r58 podName:9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc nodeName:}" failed. No retries permitted until 2025-09-09 13:09:11.181196845 +0000 UTC m=+225563.950173486 (durationBeforeRetry 2m2s). Error: MountVolume.SetUp failed for volume "kube-api-access-52r58" (UniqueName: "kubernetes.io/projected/9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc-kube-api-access-52r58") pod "pushprox-kube-proxy-client-9djm4" (UID: "9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc") : failed to fetch token: Post "https://127.0.0.1:6443/api/v1/namespaces/cattle-monitoring-system/serviceaccounts/pushprox-kube-proxy-client/token": read tcp 127.0.0.1:51706->127.0.0.1:6443: read: connection reset by peer
[+116 similar | E0909 13:07:09.181236 → E0909 13:21:43.418369 | fqdn×1 {kubernetes.io}, ipv4×1 {127.0.0.1}, k8s_namespace×1 {<FQDN><PATH>}, k8s_volume×1 {oidc-token}, name×14, number×1, path×34, quoted_string×19, uuid×16]
E0909 13:21:43.418369    3116 nestedpendingoperations.go:348] Operation for "{volumeName:kubernetes.io/projected/b39ae9d7-1732-44cd-bdc5-9eded447db57-kube-api-access-tp9r4 podName:b39ae9d7-1732-44cd-bdc5-9eded447db57 nodeName:}" failed. No retries permitted until 2025-09-09 13:23:45.418347157 +0000 UTC m=+226438.187323798 (durationBeforeRetry 2m2s). Error: MountVolume.SetUp failed for volume "kube-api-access-tp9r4" (UniqueName: "kubernetes.io/projected/b39ae9d7-1732-44cd-bdc5-9eded447db57-kube-api-access-tp9r4") pod "traefik-jp8rf" (UID: "b39ae9d7-1732-44cd-bdc5-9eded447db57") : failed to fetch token: Post "https://127.0.0.1:6443/api/v1/namespaces/traefik/serviceaccounts/traefik/token": net/http: TLS handshake timeout
W0909 13:07:12.237366    3116 transport.go:356] Unable to cancel request for *otelhttp.Transport
[+37 similar | W0909 13:07:12.237366 → W0909 13:21:42.989676 | number×1, path×1 {transport.go:356]}]
W0909 13:21:42.989676    3116 transport.go:356] Unable to cancel request for *otelhttp.Transport
...

Original: 2,000 lines → 103 lines (94.8% reduction)
```
<!-- gen:example:end -->

On a full 70k-line production kubelet log this same run folds
70,548 → 357 lines (99.5%, measured on v0.4.4) — the example above is the
committed 2,000-line slice of that log, regenerated and verified on every
CI run.

Three distinct problems, not 70,000. And the enriched markers tell you
exactly which UUIDs, volumes, and IPs were affected — information that
used to require re-running the tool.

## For Coding Agents & LLMs

70,000 log lines burn context and bury the signal. Pipe through lessence first — the agent sees 50 distinct patterns, not 70,000 repeated lines.

```bash
kubectl logs pod/api | lessence | claude -p "what's wrong?"
kubectl logs pod/api | lessence --preflight | claude -p "analyze this log report"
```

### Structured output for agents: `--format json`

For programmatic consumption, `--format json` emits a JSONL stream —
one JSON object per folded group plus a terminating summary record.
Each group record carries per-token-type rollup metadata: distinct
counts, deterministic samples, a capped flag, a raw time range, and exact
per-file locations for its first and last representatives. Stdin records use
`source: null` because no original filename is known.
The terminal summary includes a `completeness` contract with exact,
lower-bound, or unknown counts for input skipped by safety limits, groups
omitted by `--top`/`--summary`/`--fit`, and variation values hidden by sampling
or rollup caps.
Agents can answer "which pods?", "how many distinct UUIDs?", "when did
this start?" from a single invocation without re-reading the log.

```bash
kubectl logs pod/api | lessence --format json \
  | jq -r 'select(.type == "group" and .count >= 100)
           | "\(.normalized): \(.variation.UUID.distinct_count) distinct UUIDs"'
```

Full schema: [`docs/format-json-schema.md`](docs/format-json-schema.md).
Determinism is guaranteed (same input → byte-identical output, modulo
`elapsed_ms`); the rollup parameters are corpus-calibrated, see
[`docs/rollup-calibration.md`](docs/rollup-calibration.md).

## What It Does

lessence finds log lines that say the same thing with different details — different timestamps, IPs, pod names, request IDs — and folds them together. You see every unique message once, with a count of how many times it happened.

```
sort | uniq -c | sort -rn    # can't handle varying timestamps, IPs, UUIDs
grep -c "error"               # counts but doesn't show patterns
lessence                      # normalizes variables, then groups
```

## Install

```bash
cargo install lessence          # from crates.io (requires Rust 1.90+)
cargo binstall lessence         # prebuilt binary via cargo-binstall
```

Or download a binary from [GitHub Releases](https://github.com/air-gapped/lessence/releases/latest) for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), and Windows.

On macOS, you may need to remove the quarantine flag: `xattr -d com.apple.quarantine lessence`

## Usage

```bash
# Pipe anything with repetitive output
kubectl logs -f pod/api-server | lessence
journalctl -u nginx --since today | lessence
make build 2>&1 | lessence
docker-compose logs | lessence

# What's going on? One screen, no scrolling
kubectl logs pod/api-server | lessence --human

# Files or stdin — both work
lessence app.log                          # direct file argument
lessence app.log server.log worker.log    # multiple files
lessence --essence < app.log              # stdin works too

# Markdown report
lessence --format markdown app.log > report.md

# Mask emails before sharing logs
lessence --sanitize-pii app.log
```

## Essence Mode

Sometimes you want to see *what* is happening, not *when*. `--essence` strips all timestamps:

```
$ lessence --essence < app.log
<TIMESTAMP> ERROR: Database connection failed
<TIMESTAMP> INFO: User authenticated successfully
```

Two patterns. The timestamps don't matter — the database is down and auth is working.

## Real-World Compression

| Log Source | Lines In | Lines Out | Reduction | Measured on |
|-----------|--------:|---------:|----------:|------------:|
| Kubernetes kubelet | 70,548 | 357 | 99.5% | v0.4.5 |
| ArgoCD server | 60,849 | 8 | 99.9% | v0.4.5 |
| PostgreSQL primary | 54,066 | 92 | 99.8% | v0.4.5 |
| Cilium networking | 38,145 | 376 | 99.0% | v0.4.5 |
| Rancher | 22,433 | 243 | 98.9% | v0.4.5 |
| journalctl (7 days) | 655,103 | 1,870 | 99.7% | v0.4.5 |

Measurements on production corpora that are not distributable; the
headline example above is the only CI-verified number.

## Flags

<!-- gen:flags:begin -->
```
--threshold <THRESHOLD>    Percent of tokens two lines must share to group (0-100). Raise (e.g. 85) for stricter, per-message splitting; lower for more folding [default: 75]
--min-collapse <MIN_COLLAPSE>    Minimum lines before folding (min: 3) [default: 3]
--disable-patterns <DISABLE_PATTERNS>    Disable specific pattern groups (comma-separated). Valid names: timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name
--quiet (alias: --no-stats) (-q)    Disable statistics output (enabled by default) [default: false]
--preserve-color    Preserve ANSI color codes (stripped by default) [default: false]
--summary    One-line-per-pattern frequency summary (use with --top N for compact overview) [default: false]
--preflight    JSON analysis report to stdout (for automation/CI) [default: false]
--format <FORMAT>    Output format: text (default), markdown, json (JSONL for agent consumption) [default: text]
--essence    Enable essence mode (timestamp removal/tokenization for temporal independence) [default: false]
--threads <THREADS>    Number of threads for parallel processing (1=single-threaded, auto-detect if not specified)
--sanitize-pii    Enable PII sanitization (mask email addresses and sensitive data, default: disabled) [default: false]
--max-line-length <MAX_LINE_LENGTH>    Maximum line length in bytes (skip lines exceeding this, supports K/M/G suffixes: 10M, 1G, default: 1M)
--max-lines <MAX_LINES>    Maximum number of lines to process (stop after this count, default: no limit)
--stats-json    Emit JSON statistics to stderr (replaces human-readable stats) [default: false]
--top <TOP>    Show only the N most frequent patterns, sorted by count
--fit (alias: --human)    Quick human-readable overview that fits your screen — no scrolling [default: false]
--fail-on-pattern <FAIL_ON_PATTERN>    Exit 1 if any input line matches this regex (for CI gating)
--completions <COMPLETIONS>    Generate shell completion script and exit
FILE...    Input files (reads stdin if none given, use - for explicit stdin)
```
<!-- gen:flags:end -->

### Pattern Types

<!-- gen:patterns:begin -->
lessence recognizes 15 pattern groups (the valid `--disable-patterns` names):

```
timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name
```
<!-- gen:patterns:end -->

Disable any with `--disable-patterns timestamp,email`.

## How It Works

1. **Normalize** — replace variable parts with tokens (`<IP>`, `<TIMESTAMP>`, `<UUID>`)
2. **Group** — match lines with similar normalized forms
3. **Fold** — collapse groups of 3+ into representative line + count

Parallel by default — uses all CPU cores for normalization.

## Agent Skill

A `SKILL.md` is included at `.claude/skills/lessence/` that teaches AI coding agents when and how to use lessence — triage workflows, flag reference, common pitfalls. The `SKILL.md` format is supported by [Claude Code](https://claude.ai/code), [OpenCode](https://opencode.ai), and other agents that scan `.claude/skills/`.

**If you cloned the repo**, the skill is already active in this project directory.
The canonical skill lives in `.claude/skills/lessence`; the
`.agents/skills/lessence` symlink exposes the same files to Codex and Pi.
OpenCode recognizes both locations. On Windows, Git must be configured to
check out repository symlinks as symlinks.

**To install globally** (available in all projects):

```bash
mkdir -p ~/.claude/skills/lessence/references
curl -fsSL https://raw.githubusercontent.com/air-gapped/lessence/main/.claude/skills/lessence/SKILL.md \
  -o ~/.claude/skills/lessence/SKILL.md
curl -fsSL https://raw.githubusercontent.com/air-gapped/lessence/main/.claude/skills/lessence/references/flags.md \
  -o ~/.claude/skills/lessence/references/flags.md
```

Then just mention logs, errors, or "what's not normal" and the skill triggers.

## Development

```bash
cargo build --release
cargo test
```

## Name

Started as "logfold" but that was taken. **lessence** = **l**og **essence**, with a nod to the French *l'essence* — the essential nature of a thing.

## License

MIT
