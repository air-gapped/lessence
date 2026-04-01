## 1. Dependencies

- [x] 1.1 Add `clap_complete = "4"` to Cargo.toml dependencies

## 2. Implementation

- [x] 2.1 Add `--completions <shell>` flag to Cli struct using `clap_complete::Shell` as value type
- [x] 2.2 Add early exit in main() after Cli::parse() to handle completions before config construction

## 3. Verify

- [x] 3.1 Test: `lessence --completions bash` produces valid script containing "lessence"
- [x] 3.2 Test: `lessence --completions zsh` produces output
- [x] 3.3 Test: `lessence --completions invalid` fails with error
- [x] 3.4 `cargo clippy --all-targets` passes
