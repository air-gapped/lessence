# lessence — extract the essence of your logs

Your pod is crash-looping. `kubectl logs` dumps 70,000 lines. What's actually broken?

<!-- gen:example:begin -->
```
$ lessence kubelet.log

--- lessence briefing: kubelet_2k.log (2,000 lines)
span:    E0909 13:07:09.181236 → E0909 13:21:46.847407  (14m 37s, 2.281 lines/s)
shape:   █▇▇▆▆▆▆▅▇▆█▅▇▅▇▆▆▇▅▇▆▇▅▅  busiest 09-09 13:07 +37s holds 70 (5.8%)
format:  plain 2,000 (100%)
levels:  error 925 (78.9%), warn 68 (5.8%), info 179 (15.3%) — on 1,172 lines (59%)
top templates (10 of 56, 68% of all lines):
   13.1%  261                	Is the agent running?
   13.1%  261                	rpc error: code = Unknown desc = failed to setup network for sandbox "<HASH>": plugin type=<QUOTED_…
    8.7%  174                 > pod="<NAMESPACE>/<POD_NAME>"
...
report: ~/.local/state/lessence/reports/run-<date>-<id>/report.jsonl  file: complete  input: complete  run: run-<date>-<id>  size: <n> bytes  groups: 56 total, 40 selected, 17 printed, 39 omitted
[73x] id=0 E0909 13:07:09.181236 → E0909 13:21:02.461198
<TIMESTAMP>    <PID> nestedpendingoperations.go:348] Operation for "{volumeName:<K8S_NAME> podName:<UUID> nodeName:}" failed. No retries permitted until <TIMESTAMP> UTC m=+<DECIMAL> (durationBeforeRetry <DURATION>). Error: MountVolume.SetUp failed for volume <VARIES> (UniqueName: "<K8S_NAME>") pod <VARIES> (UID: "<UUID>") : failed to fetch token: Post "<PATH>": read tcp <IP>:<PORT>-><IP>:<PORT>: read: connection reset by peer
variation: DURATION>=64 …[report kept 0]  IPV4=1 [127.0.0.1]  K8S_NAMESPACE=16 [kubernetes.io/projected/<UUID>-kube-api-access-52r58|kubernetes.io/projected/<UUID>-kube-api-access-b5ws4|kubernetes.io/projected/<UUID>-kube-api-access-gm4xp] …[showing 3 of 7] …[report kept 7]  K8S_VOLUME=1 [oidc-token]  NAME=29 [kube-api-access-b5ws4|kube-api-access-gm4xp|kube-api-access-l97vx] …[showing 3 of 7] …[report kept 7]  PATH=15 [https://127.0.0.1:6443/api/v1/namespaces/gpu-operator/serviceaccounts/nvidia-con|https://127.0.0.1:6443/api/v1/namespaces/gpu-operator/serviceaccounts/nvidia-dcg|https://127.0.0.1:6443/api/v1/namespaces/gpu-operator/serviceaccounts/nvidia-ope] …[showing 3 of 7] …[report kept 7]  PID=1 …[report kept 0]  PORT>=64 …[report kept 0]  QUOTED_STRING=11 ["<COMPONENT>-<SUFFIX>"|"<K8S_NAME>"|"<UUID>"] …[showing 3 of 7] …[report kept 7]  TIMESTAMP>=64 …[report kept 0]  UUID=15 [01af48d9-3471-4acf-93aa-689c01b31dff|1f0c6b7f-a1f8-4128-be41-448fb016a65a|1f4fdc9d-12d9-451b-9456-110b32706d57] …[showing 3 of 7] …[report kept 7]  VARIES=7 ["kube-api-access-<SUFFIX>"|"<COMPONENT>-<SUFFIX>"|"csi-rbdplugin-<SUFFIX>"] …[showing 3 of 7]  (report-sampled: DURATION, K8S_NAMESPACE, NAME, PATH, PID, PORT, QUOTED_STRING, TIMESTAMP, UUID — the report itself holds fewer values than the group had)
previewed here: samples
[39x] id=1 W0909 13:07:12.237366 → W0909 13:21:42.989676
<TIMESTAMP>    <PID> transport.go:356] Unable to cancel request for *otelhttp.Transport
variation: PID=1 …[report kept 0]  TIMESTAMP=39 …[report kept 0]  (report-sampled: PID, TIMESTAMP — the report itself holds fewer values than the group had)
...
report: ~/.local/state/lessence/reports/run-<date>-<id>/report.jsonl  file: complete  input: complete  run: run-<date>-<id>  size: <n> bytes  groups: 56 total, 40 selected, 17 printed, 39 omitted
recipes (the report is JSONL; none of these prints the whole file):
  top 40 by count:   jq -r 'select(.type=="group")|"\(.count)\t\(.id)\t\(.normalized[0:120])"' -- '~/.local/state/lessence/reports/run-<date>-<id>/report.jsonl' | sort -rn | head -40
  ...
```
<!-- gen:example:end -->

That is the committed 2,000-line slice of a production kubelet log, run on
every CI build so the example is always real output.

## What a run gives you

`lessence app.log` does two things. It writes the **report**, the complete
folded JSON of the run (one record per distinct event, with its count, its
first and last raw lines and the values that varied), to
`~/.local/state/lessence/reports/<run>/report.jsonl`. And it prints an
**overview** on stdout, bounded to 16 KiB: the **briefing** (the summary block
at the top), the **locator** (the line naming the report file and counting the
groups it holds, shows and left out), a selection of the rarest and most
frequent **groups** (one distinct event with its count), and four `jq` recipes
that query the report by group id. The report is complete; stdout is a
selection, and the locator says how many groups it left out.

`--overview all` prints every group with no budget. `--report-dir` moves the
reports, `--report-max-bytes` caps one run (default 1G). lessence never deletes
a report; `rm -r ~/.local/state/lessence/reports` when you want the space.

`lessence --no-report app.log` skips the file and streams the folded text
instead. **Use `--no-report` for `tail -f` or any source that never ends**: the
report is written at end of input.

## For Coding Agents & LLMs

70,000 log lines burn context and bury the signal. Pipe through lessence first: the agent sees each distinct event once, with its count, and can query the report for anything the overview left out.

```bash
kubectl logs pod/api | lessence | claude -p "what's wrong?"
kubectl logs pod/api | lessence --preflight | claude -p "analyze this log report"
```

Which output for which need:

- the default run for orientation plus a queryable report file;
- `--format json` for the whole fold as JSONL on stdout, nothing saved;
- `--preflight` for a one-object health summary of the log;
- `--explain` is a developer mode that says why lines folded or split.

### Structured output for agents: `--format json`

`--format json` emits a JSONL stream —
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
Same input gives the same output, except the elapsed-time field; the rollup
parameters are corpus-calibrated, see
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

Sometimes you want to see *what* is happening, not *when*. `--essence` replaces every timestamp with `<TIMESTAMP>` so lines that differ only in time fold together:

```
$ lessence --essence --no-report -q app.log
<TIMESTAMP> ERROR: Database connection failed
<TIMESTAMP> INFO: User authenticated successfully
```

Two patterns. The timestamps don't matter — the database is down and auth is working.

## Real-World Compression

<!-- gen:compression:begin -->
<!-- gen:compression:at 4d58da8db -->
Measured on v0.8.1 (commit 4d58da8db) on production logs that are not
distributable. Every distinct message is its own event, so these counts are
lower than a looser folder would give.

| Log source | Lines in | Lines out | Reduction |
|-----------|--------:|---------:|----------:|
| Kubernetes kubelet | 70,548 | 733 | 99.0% |
| ArgoCD server | 60,849 | 21 | 99.97% |
| PostgreSQL primary | 54,066 | 96 | 99.8% |
| Cilium networking | 38,145 | 1,038 | 97.3% |
| Rancher | 22,433 | 311 | 98.6% |
| journalctl (7 days) | 655,103 | 3,386 | 99.5% |
<!-- gen:compression:end -->

Measured before each release on production logs that are not distributable;
the release check refuses a table generated on older folding code.

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
OpenCode recognizes both locations.

`lessence --help` opens with a block addressed to agents: skip the skill if it
is already in your context, otherwise `lessence --skill`, then the JSON surface.
People get a short help with `lessence --help-human`.

**To install globally** (available in all projects), from the binary you
have — the skill is embedded at build time, so it always matches the
installed version:

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
