# lessence — extract the essence of your logs

Your pod is crash-looping. `kubectl logs` dumps 70,000 lines. What's actually broken?

```
$ kubectl logs deployment/api | lessence

E0909 13:07:09 nestedpendingoperations.go:348] Operation for volume failed...
[+1273 similar, varying: UUID, hash, name, path, timestamp]
W0909 13:07:12 transport.go:356] Unable to cancel request...
[+1295 similar, varying: number, timestamp]
E0909 13:07:12 controller.go:145] Failed to ensure lease exists...
[+12 similar, varying: timestamp]
...

Original: 70,548 lines → 1,129 lines (98.4% reduction)
```

Three distinct problems, not 70,000. Now you know where to look.

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

# Strip timestamps to see pure patterns
lessence --essence < app.log

# Markdown report
lessence --format markdown < app.log > report.md

# Mask emails before sharing logs
lessence --sanitize-pii < app.log
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

| Log Source | Lines In | Lines Out | Reduction |
|-----------|--------:|---------:|----------:|
| Kubernetes kubelet | 70,548 | 1,129 | 98.4% |
| ArgoCD server | 60,849 | 8 | 99.9% |
| PostgreSQL primary | 54,066 | 51 | 99.9% |
| Cilium networking | 38,145 | 1,253 | 96.7% |
| Rancher | 22,433 | 583 | 97.4% |
| journalctl (7 days) | 655,103 | 3,132 | 99.5% |

## Flags

```
--fit (--human)             One screen overview — no scrolling, stays visible
--summary                  One-line-per-pattern frequency overview
--preflight                JSON analysis report (for automation/CI)
--essence                  Strip timestamps, see pure patterns
--threads N                Thread count (default: all cores)
--format text|markdown     Output format
-q, --quiet                Hide statistics footer (alias: --no-stats)
--stats-json               Emit JSON statistics to stderr
--top N                    Show only N most frequent patterns by count
--fail-on-pattern REGEX    Exit 1 if input matches (for CI gating)
--completions SHELL        Generate shell completions (bash/zsh/fish)
--threshold 75             Similarity % (0-100, lower = more grouping)
--min-collapse 3           Min similar lines before folding (min: 2)
--disable-patterns X,Y     Turn off specific detectors
--sanitize-pii             Replace emails with <EMAIL>
--preserve-color           Keep ANSI escape codes
```

### Pattern Types

lessence recognizes 16 types of variable content:

timestamp, email, path, json, uuid, network, hash, process, kubernetes, http-status, brackets, key-value, duration, name, quoted-string, decimal

Disable any with `--disable-patterns timestamp,email`.

## How It Works

1. **Normalize** — replace variable parts with tokens (`<IP>`, `<TIMESTAMP>`, `<UUID>`)
2. **Group** — match lines with similar normalized forms
3. **Fold** — collapse groups of 3+ into representative line + count

Parallel by default — uses all CPU cores for normalization.

## Agent Skill

A `SKILL.md` is included at `.claude/skills/lessence/` that teaches AI coding agents when and how to use lessence — triage workflows, flag reference, common pitfalls. The `SKILL.md` format is supported by [Claude Code](https://claude.ai/code), [OpenCode](https://opencode.ai), and other agents that scan `.claude/skills/`.

**If you cloned the repo**, the skill is already active in this project directory.

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
cargo test               # 328 tests
```

## License

MIT
