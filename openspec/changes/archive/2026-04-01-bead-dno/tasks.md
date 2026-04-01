## 1. CLI Argument Changes

- [x] 1.1 Add `files: Vec<PathBuf>` positional argument to `Cli` struct in `src/main.rs`
- [x] 1.2 Add `open_inputs` helper function that returns `Vec<Box<dyn BufRead>>` — stdin when empty, file readers otherwise, `-` as explicit stdin

## 2. Input Plumbing

- [x] 2.1 Replace hardcoded `BufReader::new(stdin)` in main processing path with `open_inputs(&cli.files)`
- [x] 2.2 Replace hardcoded `BufReader::new(stdin)` in preflight processing path with `open_inputs(&cli.files)`
- [x] 2.3 Chain multiple readers into a single line iterator for the processing loop

## 3. Error Handling

- [x] 3.1 Warn on stderr and skip files that fail to open (`lessence: <path>: <error>`)
- [x] 3.2 Exit non-zero when ALL inputs fail (no valid input processed)

## 4. Tests

- [x] 4.1 Integration test: `lessence app.log` produces same output as `lessence < app.log`
- [x] 4.2 Integration test: multiple files concatenated into one compressed output
- [x] 4.3 Integration test: no arguments reads from stdin (backwards compatibility)
- [x] 4.4 Integration test: nonexistent file warns on stderr, valid files still processed
- [x] 4.5 Integration test: `-` reads from stdin
