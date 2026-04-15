# CLAUDE.md - lessence

lessence ("log essence") — a CLI tool that extracts the essence of massive logs, preserving 100% of unique information while folding repetitive noise. Pipe any log through it to see the signal.

```bash
lessence app.log                          # file argument (or stdin via <)
kubectl logs pod | lessence               # kubernetes noise reduction
lessence --human app.log                  # one screen, no scrolling
lessence --essence app.log                # remove timestamps, show patterns
lessence --format markdown app.log        # markdown output
```

## Build & Test

```bash
cargo build --release
cargo test --lib                          # unit tests
cargo test --tests                        # integration tests
./target/release/lessence --version       # verify binary
```

## Architecture

**Pipeline**: stdin -> normalize -> group similar -> fold duplicates -> stdout

```
src/
  main.rs              # CLI entry (clap)
  config.rs            # Configuration
  folder.rs            # Core folding engine (parallel via rayon)
  normalize.rs         # Pattern normalization + similarity matching
  patterns/            # 16 pattern detectors (timestamp, email, hash, network, ...)
    timestamp/         # Unified timestamp detection (30+ formats, registry-based)
  essence/             # --essence mode: timestamp removal for pattern analysis
  output/              # Text and markdown formatters
  constitutional.rs    # Compliance test helpers
  analyzer.rs          # Log analysis
  cli/                 # CLI argument definitions
```

**How folding works**: Lines are normalized (variable parts replaced with tokens like `<IP>`, `<TIMESTAMP>`, `<UUID>`), then grouped by similarity. Groups of 3+ similar lines are collapsed to a representative line + count.

**Parallel processing**: When threads > 1 (default), lines are batched (10,000 at a time), normalized in parallel via rayon, then clustered sequentially.

## Key Flags

```
--fit (--human)             One screen overview — no scrolling, stays visible
--summary                  One-line-per-pattern frequency overview (use with --top N)
--preflight                JSON analysis report to stdout (for automation/CI)
--essence                  Remove timestamps for pure content analysis
--threads N                Thread count (default: auto, use 1 for single-threaded)
--format text|markdown     Output format (default: text)
-q, --quiet                Suppress statistics footer (alias: --no-stats)
--stats-json               Emit JSON statistics to stderr
--top N                    Show only N most frequent patterns, sorted by count
--fail-on-pattern REGEX    Exit 1 if any input line matches (for CI gating)
--completions SHELL        Generate shell completions (bash/zsh/fish/elvish/powershell)
--disable-patterns X,Y     Disable specific pattern detectors
--threshold 75             Similarity percentage (0-100)
--min-collapse 3           Minimum lines before folding (min: 2)
--sanitize-pii             Mask email addresses
--preserve-color           Keep ANSI codes
```

Valid pattern names (15): `timestamp`, `hash`, `network`, `uuid`, `email`, `path`, `duration`, `json`, `kubernetes`, `http-status`, `brackets`, `key-value`, `process`, `quoted-string`, `name`

## Design Principles

- **Zero data loss** — 100% of unique information preserved. Only repetitive patterns are compressed.
- **Parallel by default** — must outperform single-thread on multi-core systems.
- **Complete coverage** — all pattern types fully implemented. No subset shortcuts.
- **Security** — all regex patterns resist ReDoS. Input validation enforced. PII sanitization available. Security overhead < 5%.
- **CLI pipeline tool** — stdin/stdout, non-destructive, Unix composable.
- **Test-first** — if it's not tested, it's not done.

## Commits

Conventional commits drive release notes via release-please. The commit type
controls what appears in the changelog — choose carefully:

- `feat:` / `fix:` / `perf:` — **user-facing** changes. These appear in release notes.
- `test:` / `refactor:` / `style:` — **internal** changes. Hidden from release notes.
- `chore:` / `docs:` / `ci:` / `build:` — **infrastructure**. Hidden from release notes.

The first line of the commit message becomes the changelog entry. Write it for
users, not developers: "default cap of 30 patterns in --summary mode" is better
than "add DEFAULT_SUMMARY_CAP constant to finish_summary".

## Safety

- Commit before risky operations (`git add . && git commit -m "protect work"`)
- Never run destructive git commands without asking
- Never create planning/scratch files inside the project tree — use /tmp or keep it in conversation
- Before `git add`, verify files aren't matched by .gitignore (`git check-ignore <path>`)

## Skills

Project-specific skills in `.claude/skills/` load on demand:
- **testing** — test commands, security testing, ReDoS patterns
- **pattern-dev** — detection order, adding new patterns, normalization internals
- **release** — versioning, changelog, publishing workflow
