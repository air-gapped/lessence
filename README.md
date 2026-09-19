# lessence — extract the essence of your logs

Your pod is crash-looping. `kubectl logs` dumps 70,000 lines. What's actually broken?

<!-- gen:example:begin -->
```
$ lessence --no-report kubelet.log

E0909 13:07:09.181236    3116 nestedpendingoperations.go:348] Operation for "{volumeName:kubernetes.io/projected/9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc-kube-api-access-52r58 podName:9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc nodeName:}" failed. No retries permitted until 2025-09-09 13:09:11.181196845 +0000 UTC m=+225563.950173486 (durationBeforeRetry 2m2s). Error: MountVolume.SetUp failed for volume "kube-api-access-52r58" (UniqueName: "kubernetes.io/projected/9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc-kube-api-access-52r58") pod "pushprox-kube-proxy-client-9djm4" (UID: "9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc") : failed to fetch token: Post "https://127.0.0.1:6443/api/v1/namespaces/cattle-monitoring-system/serviceaccounts/pushprox-kube-proxy-client/token": read tcp 127.0.0.1:51706->127.0.0.1:6443: read: connection reset by peer
[+71 similar | E0909 13:07:09.181236 → E0909 13:21:02.461198 | ipv4×1 {127.0.0.1}, k8s_namespace×16, k8s_volume×1 {oidc-token}, name×29, path×15, pid×1, quoted_string×11, uuid×15, varies×7 {"kube-api-access-<SUFFIX>"×69, "<COMPONENT>-<SUFFIX>"×52, "csi-rbdplugin-<SUFFIX>"×8, "cilium-envoy-<SUFFIX>"×5, "<VOLUME_NAME>"×4, "virt-handler-<SUFFIX>"×4, <QUOTED_STRING>×4}]
E0909 13:21:02.461198    3116 nestedpendingoperations.go:348] Operation for "{volumeName:kubernetes.io/projected/1f4fdc9d-12d9-451b-9456-110b32706d57-kube-api-access-tldk7 podName:1f4fdc9d-12d9-451b-9456-110b32706d57 nodeName:}" failed. No retries permitted until 2025-09-09 13:23:04.461171825 +0000 UTC m=+226397.230148697 (durationBeforeRetry 2m2s). Error: MountVolume.SetUp failed for volume "kube-api-access-tldk7" (UniqueName: "kubernetes.io/projected/1f4fdc9d-12d9-451b-9456-110b32706d57-kube-api-access-tldk7") pod "virt-handler-gjcp7" (UID: "1f4fdc9d-12d9-451b-9456-110b32706d57") : failed to fetch token: Post "https://127.0.0.1:6443/api/v1/namespaces/kubevirt/serviceaccounts/kubevirt-handler/token": read tcp 127.0.0.1:33740->127.0.0.1:6443: read: connection reset by peer
W0909 13:07:12.237366    3116 transport.go:356] Unable to cancel request for *otelhttp.Transport
[+37 similar | W0909 13:07:12.237366 → W0909 13:21:42.989676 | pid×1]
W0909 13:21:42.989676    3116 transport.go:356] Unable to cancel request for *otelhttp.Transport
...

Original: 2,000 lines → 151 lines (92.5% reduction)
```
<!-- gen:example:end -->

The example above is the committed 2,000-line slice of a 70k-line production
kubelet log, regenerated and verified on every CI run; the full log's numbers
are in the compression table below.

Three distinct problems, not 70,000. And the enriched markers tell you
exactly which UUIDs, volumes, and IPs were affected — information that
used to require re-running the tool.

## The default run saves a report

`lessence app.log` writes the **complete** folded JSON of the run — the same
schema-1 records `--format json` emits — to `report.jsonl` in a fresh run
directory under `$XDG_STATE_HOME/lessence/reports` (never the working
directory), and prints a **byte-bounded overview** of that file on stdout: the
briefing, a locator line naming the report and what it holds, the rarest and
most frequent groups, and four jq recipes that query the report by group id.

Nothing is lost and nothing is hidden: the report is complete, stdout is
bounded to 16 KiB by default, and the locator says exactly how many groups
were selected, printed and omitted. `--overview all` prints every group with no
budget; `--report-dir` and `--report-max-bytes` move and cap the file; the
report directory grows until you delete it.

The example above uses `--no-report`, which skips the file and streams the
folded text as it always did. **Use `--no-report` for `tail -f` or any source
that never reaches EOF** — the report needs input EOF to be written.

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
kubectl logs -f pod/api-server | lessence --no-report   # live source: no EOF, no report
journalctl -u nginx --since today | lessence
make build 2>&1 | lessence
docker-compose logs | lessence

# What's going on? One screen, no scrolling
kubectl logs pod/api-server | lessence --fit

# Files or stdin — both work
lessence app.log                          # direct file argument
lessence app.log server.log worker.log    # multiple files
lessence --essence < app.log              # stdin works too

# Markdown report
lessence --format markdown app.log > report.md

# Mask emails and credentials before sharing logs
lessence --sanitize-pii app.log

# Also mask hosts and addresses; pseudonyms keep the fold (same host, same tag)
lessence --sanitize host:pseudonym,ip app.log
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

<!-- gen:compression:begin -->
<!-- gen:compression:at b61c01142 -->
Measured on v0.7.0 (commit b61c01142) on production logs that are not
distributable. Since 0.5.0 the message text is part of an event's identity, so
output is larger than in older tables and hides less.

| Log source | Lines in | Lines out | Reduction |
|-----------|--------:|---------:|----------:|
| Kubernetes kubelet | 70,548 | 733 | 99.0% |
| ArgoCD server | 60,849 | 21 | 100.0% |
| PostgreSQL primary | 54,066 | 96 | 99.8% |
| Cilium networking | 38,145 | 1,038 | 97.3% |
| Rancher | 22,433 | 311 | 98.6% |
| journalctl (7 days) | 655,103 | 3,386 | 99.5% |
<!-- gen:compression:end -->

The headline example above is the only CI-verified number; this table is
regenerated locally before every release and the release check refuses a
table older than the folding code.

## Flags

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

`lessence --help` opens with a block addressed to agents: skip the skill if it
is already in your context, otherwise `lessence --skill`, then the JSON surface.
People get a short help with `lessence --help-human`.

**To install globally** (available in all projects), from the binary you
have — the skill is embedded at build time, so it always matches the
installed version (the pattern comes from [herdr](https://github.com/herdrdev/herdr)'s `--skill`):

```bash
mkdir -p ~/.claude/skills/lessence/references
lessence --skill > ~/.claude/skills/lessence/SKILL.md
lessence --skill flags > ~/.claude/skills/lessence/references/flags.md
```

Re-run the two lines after upgrading lessence.

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
