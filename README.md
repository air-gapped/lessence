# lessence

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
cargo install --path .
```

Requires Rust 1.90+. Single binary, no runtime dependencies.

## Usage

```bash
# Pipe anything with repetitive output
kubectl logs -f pod/api-server | lessence
journalctl -u nginx --since today | lessence
make build 2>&1 | lessence
docker-compose logs | lessence

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
--essence                  Strip timestamps, see pure patterns
--threads N                Thread count (default: all cores)
--format text|markdown     Output format
--no-stats                 Hide statistics footer
--stats-json               Emit JSON statistics to stderr
--threshold 85             Similarity % (0-100, lower = more grouping)
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

## Development

```bash
cargo build --release
cargo test               # 328 tests
```

## License

MIT
