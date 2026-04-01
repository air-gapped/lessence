## 1. Config & CLI

- [x] 1.1 Add `fail_pattern: Option<String>` to Config
- [x] 1.2 Add `--fail-on-pattern <regex>` flag to Cli struct
- [x] 1.3 Wire flag to Config, compile regex early, exit 2 on invalid regex

## 2. Implementation

- [x] 2.1 Add `pattern_matched` flag, test each raw line with `is_match()` in all code paths (normal, summary, preflight)
- [x] 2.2 After all output is flushed, exit with code 1 if pattern matched

## 3. Tests & Verify

- [x] 3.1 Integration test: exits 1 when pattern matches
- [x] 3.2 Integration test: exits 0 when pattern does not match
- [x] 3.3 Integration test: exits 2 on invalid regex
- [x] 3.4 Integration test: output still produced when pattern matches
- [x] 3.5 Register test file in Cargo.toml
- [x] 3.6 `cargo clippy --all-targets` passes
