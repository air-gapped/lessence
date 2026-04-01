## 1. CLI and Config

- [x] 1.1 Add `--top N` flag to Cli struct in `src/main.rs` (optional usize, no default)
- [x] 1.2 Add `top_n` field to Config struct in `src/config.rs`
- [x] 1.3 Wire CLI flag to Config in main()

## 2. Folder Changes

- [x] 2.1 Add `finish_top_n(n: usize)` method to PatternFolder that returns groups sorted by count desc
- [x] 2.2 Format each group with `[Nx]` count prefix in top-N mode
- [x] 2.3 Return coverage stats (shown groups, total groups, percentage of input lines covered)

## 3. Main Processing Path

- [x] 3.1 When `--top` is set, suppress incremental output and buffer all groups
- [x] 3.2 After input consumed, call `finish_top_n()` and emit sorted output
- [x] 3.3 Print coverage footer to stderr

## 4. Tests

- [x] 4.1 Integration test: `--top 5` shows exactly 5 groups sorted by count
- [x] 4.2 Integration test: `--top N` where N > total groups shows all groups
- [x] 4.3 Integration test: without `--top`, output is unchanged (backwards compat)
- [x] 4.4 Integration test: `--top` works with file arguments
- [x] 4.5 Unit test: `finish_top_n` returns correct counts and ordering
