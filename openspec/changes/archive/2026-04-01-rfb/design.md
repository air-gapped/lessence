## Context

lessence already tracks detailed statistics in `FoldingStats` (total_lines, output_lines, collapsed_groups, lines_saved, patterns_detected, plus per-category counters). The `print_stats()` method renders these as human-readable markdown to stdout. `serde` and `serde_json` are already dependencies.

## Goals / Non-Goals

**Goals:**
- Add `--stats-json` flag that emits a single JSON object to stderr after processing
- Include all meaningful stats: input/output lines, compression ratio, groups, elapsed time, pattern category hits
- Work orthogonally with `--no-stats` (JSON replaces the human-readable footer, not in addition to it)

**Non-Goals:**
- Streaming/NDJSON output (single object at end only)
- Changing the existing human-readable stats format
- Adding stats to stdout (would break piping)

## Decisions

**1. JSON goes to stderr, not stdout**

Compressed log output owns stdout. Stats (human or JSON) go to stderr. This matches ripgrep `--stats`, pv, and other Unix tools. Allows `lessence --stats-json < app.log > compressed.log 2> stats.json`.

**2. Derive Serialize on FoldingStats + a wrapper struct**

Rather than building a JSON object by hand, derive `Serialize` on `FoldingStats` and wrap it in a `StatsJson` struct that adds computed fields (compression_ratio, elapsed_ms). This keeps the serialization in sync with any future stats additions.

```rust
#[derive(Serialize)]
struct StatsJson {
    input_lines: usize,
    output_lines: usize,
    compression_ratio: f64,
    collapsed_groups: usize,
    lines_saved: usize,
    patterns_detected: usize,
    elapsed_ms: u64,
    pattern_hits: PatternHits,
}

#[derive(Serialize)]
struct PatternHits {
    timestamps: usize,
    ips: usize,
    hashes: usize,
    // ... all non-zero categories
}
```

**3. `--stats-json` suppresses human-readable stats**

When `--stats-json` is active, the markdown stats footer is not printed. This avoids double-printing stats. `--no-stats --stats-json` is valid (no human stats, yes JSON stats). `--no-stats` alone disables both.

**4. Timing via `Instant::now()` in main**

Capture `start = Instant::now()` before processing begins, compute elapsed after processing ends. This measures wall-clock time including I/O, which is what users care about.

## Risks / Trade-offs

- [Schema stability] The JSON field names become a public API once shipped. Use snake_case, match FoldingStats field names. → Mitigated by following existing naming.
- [Zero-value fields] Including all pattern categories even when zero makes the JSON predictable (no missing keys). → Include all fields always.
