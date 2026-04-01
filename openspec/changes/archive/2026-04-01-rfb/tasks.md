## 1. Config & CLI

- [x] 1.1 Add `stats_json: bool` field to `Config` (default: false)
- [x] 1.2 Add `--stats-json` clap flag to CLI args in `src/cli/mod.rs` or `src/main.rs`
- [x] 1.3 Wire CLI flag to Config and handle interaction with `--no-stats`

## 2. Stats Serialization

- [x] 2.1 Add `#[derive(Serialize)]` to `FoldingStats` (or create a `StatsJson` wrapper struct)
- [x] 2.2 Add `elapsed_ms` and `compression_ratio` computed fields to the JSON output struct
- [x] 2.3 Add `print_stats_json()` method to `PatternFolder` that serializes to stderr

## 3. Integration

- [x] 3.1 Add `Instant::now()` timing in main before processing, pass elapsed to stats output
- [x] 3.2 Wire `--stats-json` to call `print_stats_json()` instead of `print_stats()` in all code paths (normal, summary, top-N)

## 4. Tests

- [x] 4.1 Integration test: `--stats-json` emits valid JSON on stderr
- [x] 4.2 Integration test: `--no-stats --stats-json` still emits JSON
- [x] 4.3 Integration test: `--stats-json` suppresses human-readable stats
- [x] 4.4 Integration test: JSON contains all required fields with correct types
- [x] 4.5 Register test file in Cargo.toml
