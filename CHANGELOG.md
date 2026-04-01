# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--stats-json` flag for machine-readable JSON statistics on stderr
- `--top N` flag for frequency-sorted output (show N most common patterns)
- `--fail-on-pattern <regex>` for CI exit code gating (exit 1 on match, 2 on bad regex)
- `--completions <shell>` for shell completion generation (bash/zsh/fish/elvish/powershell)
- `-q` / `--quiet` as Unix-conventional alias for `--no-stats`
- File arguments: `lessence app.log` instead of stdin only
- Snapshot tests (insta) locking down output format
- Property-based tests (proptest) for normalizer invariants
- `cargo deny` for supply chain security (licenses, advisories, bans)
- `cargo fmt` enforcement in CI
- `cargo doc` with `-D warnings` in CI
- Weekly CI: `cargo machete` (unused deps) + `cargo update --dry-run` (outdated deps)
- Release workflow with prebuilt binaries for Linux/macOS/Windows
- `cargo-binstall` metadata for fast CI installation

### Changed
- Edition 2021 to 2024 (if-let chains, stricter patterns)
- Clippy pedantic enabled with `[lints.clippy]` in Cargo.toml
- `unsafe_code = "forbid"` enforced crate-wide
- ISO 8601 timestamps in stats output (`2025-04-01T12:00:00Z`)
- `cargo nextest` replaces `cargo test` in CI
- `taiki-e/install-action` replaces `cargo install` for CI tools
- Removed `RUSTFLAGS` env from CI (was invalidating Cargo cache)
- Stripped `rustfmt.toml` to stable-only options

### Removed
- `--max-tokens` flag (fake token counting was dishonest)
- `colored` dependency (unused)
- Token estimation from stats output (misleading approximations)

### Fixed
- 270+ clippy pedantic warnings fixed across 60 files
- 3 ANSI regex compiled per-call instead of once (now `LazyLock`)
- Hidden clippy lint masked by `RUSTFLAGS` cache invalidation
- Doc comments with unescaped `<EMAIL>` breaking rustdoc

## [2.0.0] - 2026-03-31

### Added
- Initial public release as `lessence`
- 16 pattern detectors (timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name, decimal)
- Parallel processing via rayon
- `--essence` mode for temporal independence
- `--format markdown` output
- `--sanitize-pii` for email masking
- ReDoS protection on all regex patterns
- Security input limits (`--max-line-length`, `--max-lines`)

[Unreleased]: https://github.com/air-gapped/lessence/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/air-gapped/lessence/releases/tag/v2.0.0
