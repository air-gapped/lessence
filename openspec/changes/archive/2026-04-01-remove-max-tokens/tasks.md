## 1. Remove from CLI & Config

- [x] 1.1 Remove `max_tokens` field from `Cli` struct and `parse_token_count()` function in `src/main.rs`
- [x] 1.2 Remove `max_tokens` field from `Config` struct and its default in `src/config.rs`
- [x] 1.3 Remove `max_tokens` wiring in config construction in `src/main.rs`

## 2. Remove Token Logic

- [x] 2.1 Remove `count_tokens()` method from `PatternFolder` in `src/folder.rs`
- [x] 2.2 Remove token counting/limiting logic from main processing loop in `src/main.rs`
- [x] 2.3 Remove token estimation from `print_stats()` and `print_summary_stats_with_tokens()` in `src/folder.rs`
- [x] 2.4 Remove token limiting from `process_summary_mode()` in `src/folder.rs`

## 3. Clean Up References

- [x] 3.1 Remove `count_tokens()` from `LogAnalyzer` in `src/analyzer.rs` and token fields from analysis
- [x] 3.2 Update `CLAUDE.md` — remove `--max-tokens` from flags list
- [x] 3.3 Update `README.md` — remove any `--max-tokens` references
- [x] 3.4 Fix any tests that reference `max_tokens` or token counting (none found)

## 4. Verify

- [x] 4.1 `cargo clippy --all-targets` passes with zero warnings
- [x] 4.2 `cargo test --release` passes all tests
