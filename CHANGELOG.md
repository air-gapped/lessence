# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v0.1.0.html).

## [0.5.0](https://github.com/air-gapped/lessence/compare/v0.4.0...v0.5.0) (2026-04-03)


### ⚠ BREAKING CHANGES

* replace --analysis with --summary and --preflight flags

### Features

* accept file arguments (lessence app.log) ([5818e21](https://github.com/air-gapped/lessence/commit/5818e214ca36cd2554b98b59324ab8a0deb5c95a))
* add --completions flag for shell completion generation ([74d2067](https://github.com/air-gapped/lessence/commit/74d20675ef9479734ab63d11857ef5e844416ba3))
* add --fail-on-pattern for CI exit code gating ([4492d36](https://github.com/air-gapped/lessence/commit/4492d362d619f28917c05d590abc86d54cf163c3))
* add --stats-json flag for machine-readable statistics on stderr ([8c1d240](https://github.com/air-gapped/lessence/commit/8c1d240d531da47505b335b0fe74636848967673))
* add --top N flag for frequency-sorted output ([23dd032](https://github.com/air-gapped/lessence/commit/23dd032d744b32465032e721d41a117fa11458d0))
* add -q/--quiet alias for --no-stats ([43817d6](https://github.com/air-gapped/lessence/commit/43817d69b207e4a7fa31c9c351010cdb1ea39d82))
* add release workflow with prebuilt binaries for 5 platforms ([a9364d2](https://github.com/air-gapped/lessence/commit/a9364d2bde3f134d715655178e73a183aee4c807))
* auto-truncate long lines in --summary to terminal width ([0165591](https://github.com/air-gapped/lessence/commit/0165591c0b42101b413c4ecf3e3a00a42fae222c))
* default cap of 30 patterns in --summary mode ([6153a82](https://github.com/air-gapped/lessence/commit/6153a82d3bb88b6adbd1f0088e922fe495260641))
* replace --analysis with --summary and --preflight flags ([aafa6e2](https://github.com/air-gapped/lessence/commit/aafa6e28a453db1c40cd495fc78cdeb513055c41))
* switch to release-please with AI-generated release notes ([9400371](https://github.com/air-gapped/lessence/commit/940037104d065211fc2813d8d94f609f144f4129))


### Bug Fixes

* add cargo doc, cargo deny, and taiki-e/install-action to CI ([65e05e7](https://github.com/air-gapped/lessence/commit/65e05e7eb6692794289fb687c41e2b2c31fef0d9))
* add id-token permission for claude oauth in release notes ([c0d8601](https://github.com/air-gapped/lessence/commit/c0d86018a1929916a9c4ac2928ba82f28298d2e6))
* add release bot to allowed_bots, fix release notes prompt ([70e5b7e](https://github.com/air-gapped/lessence/commit/70e5b7e8e047344ce65f6bfd4e937d41acd26abf))
* add workflow_dispatch trigger and id-token to release notes ([d2addbc](https://github.com/air-gapped/lessence/commit/d2addbca60840009751d7e77449f558e529cda2d))
* checkout and upload at tag ref, not branch ref ([52618a8](https://github.com/air-gapped/lessence/commit/52618a8d314af707f223ed3aacbf5e725af88a08))
* dereference annotated tag SHAs to commit SHAs in release workflow ([a9774eb](https://github.com/air-gapped/lessence/commit/a9774eb23d92e02e91afc651d4d3e4efb627af32))
* enforce cargo fmt, fix rustfmt.toml, add format check to CI ([f3db34c](https://github.com/air-gapped/lessence/commit/f3db34c902b5479ac66c14f7b6f3c1dc8a4692e0))
* flush batch buffer in preflight/summary modes and respect --top N in summary ([bb27d3a](https://github.com/air-gapped/lessence/commit/bb27d3aa5cf88e12560d9010bf8467686ed63431))
* move release notes to separate workflow_run trigger ([988ee50](https://github.com/air-gapped/lessence/commit/988ee50652f15316126f5f78106323ae7af46a9c))
* remove cast_lossless allow, use From for safe casts ([0c9d74b](https://github.com/air-gapped/lessence/commit/0c9d74b3d4ab3789e178c84db5b2512e8358e918))
* remove hardcoded 200-char truncation from --summary output ([0722aeb](https://github.com/air-gapped/lessence/commit/0722aebb4210c23f5c956c0297980db8d116caf4))
* remove LLM references from help text ([262f6fc](https://github.com/air-gapped/lessence/commit/262f6fc400be5251f42479bd0d91b24cc4c2371d))
* remove manual_string_new allow (already fixed) ([0ba22b3](https://github.com/air-gapped/lessence/commit/0ba22b3f1d8db3f2d388485161124bf828a59586))
* remove needless_raw_string_hashes allow, strip 4 extra hashes ([e9cf051](https://github.com/air-gapped/lessence/commit/e9cf051114c2e2569a4fbe158673521713e1f8c5))
* remove redundant_closure_for_method_calls allow, simplify 8 closures ([b038062](https://github.com/air-gapped/lessence/commit/b03806251b6297b1205bf03609595431aafbe9a2))
* remove single_char_pattern allow, use char literals for splits ([0d692c9](https://github.com/air-gapped/lessence/commit/0d692c956056fd22d051f30c5687f12e1adeb782))
* remove str_split_at_newline allow, use .lines() instead ([df5130c](https://github.com/air-gapped/lessence/commit/df5130c1908bf526f5c485f39c0e887cf70343ef))
* remove uninlined_format_args allow, fix all 233 instances ([086b62f](https://github.com/air-gapped/lessence/commit/086b62f59240c254134104f9ee42b9d09dc5e81b))
* remove unreadable_literal allow, add separators to large numbers ([6572dd4](https://github.com/air-gapped/lessence/commit/6572dd44778f4577c142934ff66b693543524803))
* replace claude-code-action with bash script for release notes ([f807033](https://github.com/air-gapped/lessence/commit/f807033d2d2ddf0dba0e6a88acc2d8dcb3b599ae))
* replace unmaintained atty crate with std::io::IsTerminal ([3970da8](https://github.com/air-gapped/lessence/commit/3970da8bc8dcd65bcea8c5500286fa70b1cd44c5))
* resolve all clippy warnings, enforce in CI ([a15316b](https://github.com/air-gapped/lessence/commit/a15316b1858f3a5cef9b8b36eaa21ea71260f5ca))
* stabilize timing-dependent tests under parallel execution ([694f2d2](https://github.com/air-gapped/lessence/commit/694f2d2f880b8508a2da859ba0f449f373d5c413))
* use GitHub App token for release-please, fix deny.toml schema ([c676a45](https://github.com/air-gapped/lessence/commit/c676a45342a392001a11f2252588ee7b986990e1))
* use oauth token instead of API key for release notes ([f610a99](https://github.com/air-gapped/lessence/commit/f610a9967c5401e8650f6427e10b53a109f8e491))


### Performance

* add content-aware pre-filters to skip wasteful detector calls ([670d963](https://github.com/air-gapped/lessence/commit/670d96383c326f19c0168a40647944a62b966d15))
* change default --threshold from 85 to 75 ([b80432c](https://github.com/air-gapped/lessence/commit/b80432c2c2f1f992a796f6ddfcab3ae6636e7b2c))
* compile ANSI regex once via LazyLock instead of per-call ([9f7f8ee](https://github.com/air-gapped/lessence/commit/9f7f8ee5a1b1dcb30e67cebfe862532e222ddb49))
* optimize grouping pipeline — 45% faster parallel, 54% faster worst-case ([3905872](https://github.com/air-gapped/lessence/commit/3905872f1bdcd6e8ae1d507c5223818477f1539e))

## [0.4.0](https://github.com/air-gapped/lessence/compare/lessence-v0.3.0...lessence-v0.4.0) (2026-04-03)


### ⚠ BREAKING CHANGES

* replace --analysis with --summary and --preflight flags

### Features

* accept file arguments (lessence app.log) ([5818e21](https://github.com/air-gapped/lessence/commit/5818e214ca36cd2554b98b59324ab8a0deb5c95a))
* add --completions flag for shell completion generation ([74d2067](https://github.com/air-gapped/lessence/commit/74d20675ef9479734ab63d11857ef5e844416ba3))
* add --fail-on-pattern for CI exit code gating ([4492d36](https://github.com/air-gapped/lessence/commit/4492d362d619f28917c05d590abc86d54cf163c3))
* add --stats-json flag for machine-readable statistics on stderr ([8c1d240](https://github.com/air-gapped/lessence/commit/8c1d240d531da47505b335b0fe74636848967673))
* add --top N flag for frequency-sorted output ([23dd032](https://github.com/air-gapped/lessence/commit/23dd032d744b32465032e721d41a117fa11458d0))
* add -q/--quiet alias for --no-stats ([43817d6](https://github.com/air-gapped/lessence/commit/43817d69b207e4a7fa31c9c351010cdb1ea39d82))
* add release workflow with prebuilt binaries for 5 platforms ([a9364d2](https://github.com/air-gapped/lessence/commit/a9364d2bde3f134d715655178e73a183aee4c807))
* auto-truncate long lines in --summary to terminal width ([0165591](https://github.com/air-gapped/lessence/commit/0165591c0b42101b413c4ecf3e3a00a42fae222c))
* default cap of 30 patterns in --summary mode ([6153a82](https://github.com/air-gapped/lessence/commit/6153a82d3bb88b6adbd1f0088e922fe495260641))
* replace --analysis with --summary and --preflight flags ([aafa6e2](https://github.com/air-gapped/lessence/commit/aafa6e28a453db1c40cd495fc78cdeb513055c41))
* switch to release-please with AI-generated release notes ([9400371](https://github.com/air-gapped/lessence/commit/940037104d065211fc2813d8d94f609f144f4129))


### Bug Fixes

* add cargo doc, cargo deny, and taiki-e/install-action to CI ([65e05e7](https://github.com/air-gapped/lessence/commit/65e05e7eb6692794289fb687c41e2b2c31fef0d9))
* add id-token permission for claude oauth in release notes ([c0d8601](https://github.com/air-gapped/lessence/commit/c0d86018a1929916a9c4ac2928ba82f28298d2e6))
* add release bot to allowed_bots, fix release notes prompt ([70e5b7e](https://github.com/air-gapped/lessence/commit/70e5b7e8e047344ce65f6bfd4e937d41acd26abf))
* add workflow_dispatch trigger and id-token to release notes ([d2addbc](https://github.com/air-gapped/lessence/commit/d2addbca60840009751d7e77449f558e529cda2d))
* checkout and upload at tag ref, not branch ref ([52618a8](https://github.com/air-gapped/lessence/commit/52618a8d314af707f223ed3aacbf5e725af88a08))
* dereference annotated tag SHAs to commit SHAs in release workflow ([a9774eb](https://github.com/air-gapped/lessence/commit/a9774eb23d92e02e91afc651d4d3e4efb627af32))
* enforce cargo fmt, fix rustfmt.toml, add format check to CI ([f3db34c](https://github.com/air-gapped/lessence/commit/f3db34c902b5479ac66c14f7b6f3c1dc8a4692e0))
* flush batch buffer in preflight/summary modes and respect --top N in summary ([bb27d3a](https://github.com/air-gapped/lessence/commit/bb27d3aa5cf88e12560d9010bf8467686ed63431))
* move release notes to separate workflow_run trigger ([988ee50](https://github.com/air-gapped/lessence/commit/988ee50652f15316126f5f78106323ae7af46a9c))
* remove cast_lossless allow, use From for safe casts ([0c9d74b](https://github.com/air-gapped/lessence/commit/0c9d74b3d4ab3789e178c84db5b2512e8358e918))
* remove hardcoded 200-char truncation from --summary output ([0722aeb](https://github.com/air-gapped/lessence/commit/0722aebb4210c23f5c956c0297980db8d116caf4))
* remove LLM references from help text ([262f6fc](https://github.com/air-gapped/lessence/commit/262f6fc400be5251f42479bd0d91b24cc4c2371d))
* remove manual_string_new allow (already fixed) ([0ba22b3](https://github.com/air-gapped/lessence/commit/0ba22b3f1d8db3f2d388485161124bf828a59586))
* remove needless_raw_string_hashes allow, strip 4 extra hashes ([e9cf051](https://github.com/air-gapped/lessence/commit/e9cf051114c2e2569a4fbe158673521713e1f8c5))
* remove redundant_closure_for_method_calls allow, simplify 8 closures ([b038062](https://github.com/air-gapped/lessence/commit/b03806251b6297b1205bf03609595431aafbe9a2))
* remove single_char_pattern allow, use char literals for splits ([0d692c9](https://github.com/air-gapped/lessence/commit/0d692c956056fd22d051f30c5687f12e1adeb782))
* remove str_split_at_newline allow, use .lines() instead ([df5130c](https://github.com/air-gapped/lessence/commit/df5130c1908bf526f5c485f39c0e887cf70343ef))
* remove uninlined_format_args allow, fix all 233 instances ([086b62f](https://github.com/air-gapped/lessence/commit/086b62f59240c254134104f9ee42b9d09dc5e81b))
* remove unreadable_literal allow, add separators to large numbers ([6572dd4](https://github.com/air-gapped/lessence/commit/6572dd44778f4577c142934ff66b693543524803))
* replace claude-code-action with bash script for release notes ([f807033](https://github.com/air-gapped/lessence/commit/f807033d2d2ddf0dba0e6a88acc2d8dcb3b599ae))
* replace unmaintained atty crate with std::io::IsTerminal ([3970da8](https://github.com/air-gapped/lessence/commit/3970da8bc8dcd65bcea8c5500286fa70b1cd44c5))
* resolve all clippy warnings, enforce in CI ([a15316b](https://github.com/air-gapped/lessence/commit/a15316b1858f3a5cef9b8b36eaa21ea71260f5ca))
* stabilize timing-dependent tests under parallel execution ([694f2d2](https://github.com/air-gapped/lessence/commit/694f2d2f880b8508a2da859ba0f449f373d5c413))
* use GitHub App token for release-please, fix deny.toml schema ([c676a45](https://github.com/air-gapped/lessence/commit/c676a45342a392001a11f2252588ee7b986990e1))
* use oauth token instead of API key for release notes ([f610a99](https://github.com/air-gapped/lessence/commit/f610a9967c5401e8650f6427e10b53a109f8e491))


### Performance

* add content-aware pre-filters to skip wasteful detector calls ([670d963](https://github.com/air-gapped/lessence/commit/670d96383c326f19c0168a40647944a62b966d15))
* change default --threshold from 85 to 75 ([b80432c](https://github.com/air-gapped/lessence/commit/b80432c2c2f1f992a796f6ddfcab3ae6636e7b2c))
* compile ANSI regex once via LazyLock instead of per-call ([9f7f8ee](https://github.com/air-gapped/lessence/commit/9f7f8ee5a1b1dcb30e67cebfe862532e222ddb49))
* optimize grouping pipeline — 45% faster parallel, 54% faster worst-case ([3905872](https://github.com/air-gapped/lessence/commit/3905872f1bdcd6e8ae1d507c5223818477f1539e))

## [0.3.0](https://github.com/air-gapped/lessence/compare/v0.2.0...v0.3.0) (2026-04-03)


### Features

* auto-truncate long lines in --summary to terminal width ([0165591](https://github.com/air-gapped/lessence/commit/0165591c0b42101b413c4ecf3e3a00a42fae222c))
* default cap of 30 patterns in --summary mode ([6153a82](https://github.com/air-gapped/lessence/commit/6153a82d3bb88b6adbd1f0088e922fe495260641))


### Bug Fixes

* remove hardcoded 200-char truncation from --summary output ([0722aeb](https://github.com/air-gapped/lessence/commit/0722aebb4210c23f5c956c0297980db8d116caf4))
* replace unmaintained atty crate with std::io::IsTerminal ([3970da8](https://github.com/air-gapped/lessence/commit/3970da8bc8dcd65bcea8c5500286fa70b1cd44c5))
* stabilize timing-dependent tests under parallel execution ([694f2d2](https://github.com/air-gapped/lessence/commit/694f2d2f880b8508a2da859ba0f449f373d5c413))


### Performance Improvements

* change default --threshold from 85 to 75 ([b80432c](https://github.com/air-gapped/lessence/commit/b80432c2c2f1f992a796f6ddfcab3ae6636e7b2c))

## [0.1.2](https://github.com/air-gapped/lessence/compare/v0.1.1...v0.1.2) (2026-04-01)


### Bug Fixes

* add id-token permission for claude oauth in release notes ([c0d8601](https://github.com/air-gapped/lessence/commit/c0d86018a1929916a9c4ac2928ba82f28298d2e6))
* add workflow_dispatch trigger and id-token to release notes ([d2addbc](https://github.com/air-gapped/lessence/commit/d2addbca60840009751d7e77449f558e529cda2d))
* move release notes to separate workflow_run trigger ([988ee50](https://github.com/air-gapped/lessence/commit/988ee50652f15316126f5f78106323ae7af46a9c))
* replace claude-code-action with bash script for release notes ([f807033](https://github.com/air-gapped/lessence/commit/f807033d2d2ddf0dba0e6a88acc2d8dcb3b599ae))


### Performance Improvements

* add content-aware pre-filters to skip wasteful detector calls ([670d963](https://github.com/air-gapped/lessence/commit/670d96383c326f19c0168a40647944a62b966d15))
* optimize grouping pipeline — 45% faster parallel, 54% faster worst-case ([3905872](https://github.com/air-gapped/lessence/commit/3905872f1bdcd6e8ae1d507c5223818477f1539e))

## [0.1.1](https://github.com/air-gapped/lessence/compare/v0.1.0...v0.1.1) (2026-04-01)


### Bug Fixes

* checkout and upload at tag ref, not branch ref ([52618a8](https://github.com/air-gapped/lessence/commit/52618a8d314af707f223ed3aacbf5e725af88a08))

## 0.1.0 (2026-04-01)


### Features

* accept file arguments (lessence app.log) ([5818e21](https://github.com/air-gapped/lessence/commit/5818e214ca36cd2554b98b59324ab8a0deb5c95a))
* add --completions flag for shell completion generation ([74d2067](https://github.com/air-gapped/lessence/commit/74d20675ef9479734ab63d11857ef5e844416ba3))
* add --fail-on-pattern for CI exit code gating ([4492d36](https://github.com/air-gapped/lessence/commit/4492d362d619f28917c05d590abc86d54cf163c3))
* add --stats-json flag for machine-readable statistics on stderr ([8c1d240](https://github.com/air-gapped/lessence/commit/8c1d240d531da47505b335b0fe74636848967673))
* add --top N flag for frequency-sorted output ([23dd032](https://github.com/air-gapped/lessence/commit/23dd032d744b32465032e721d41a117fa11458d0))
* add -q/--quiet alias for --no-stats ([43817d6](https://github.com/air-gapped/lessence/commit/43817d69b207e4a7fa31c9c351010cdb1ea39d82))
* add release workflow with prebuilt binaries for 5 platforms ([a9364d2](https://github.com/air-gapped/lessence/commit/a9364d2bde3f134d715655178e73a183aee4c807))
* switch to release-please with AI-generated release notes ([9400371](https://github.com/air-gapped/lessence/commit/940037104d065211fc2813d8d94f609f144f4129))


### Bug Fixes

* add cargo doc, cargo deny, and taiki-e/install-action to CI ([65e05e7](https://github.com/air-gapped/lessence/commit/65e05e7eb6692794289fb687c41e2b2c31fef0d9))
* add release bot to allowed_bots, fix release notes prompt ([70e5b7e](https://github.com/air-gapped/lessence/commit/70e5b7e8e047344ce65f6bfd4e937d41acd26abf))
* dereference annotated tag SHAs to commit SHAs in release workflow ([a9774eb](https://github.com/air-gapped/lessence/commit/a9774eb23d92e02e91afc651d4d3e4efb627af32))
* enforce cargo fmt, fix rustfmt.toml, add format check to CI ([f3db34c](https://github.com/air-gapped/lessence/commit/f3db34c902b5479ac66c14f7b6f3c1dc8a4692e0))
* remove cast_lossless allow, use From for safe casts ([0c9d74b](https://github.com/air-gapped/lessence/commit/0c9d74b3d4ab3789e178c84db5b2512e8358e918))
* remove LLM references from help text ([262f6fc](https://github.com/air-gapped/lessence/commit/262f6fc400be5251f42479bd0d91b24cc4c2371d))
* remove manual_string_new allow (already fixed) ([0ba22b3](https://github.com/air-gapped/lessence/commit/0ba22b3f1d8db3f2d388485161124bf828a59586))
* remove needless_raw_string_hashes allow, strip 4 extra hashes ([e9cf051](https://github.com/air-gapped/lessence/commit/e9cf051114c2e2569a4fbe158673521713e1f8c5))
* remove redundant_closure_for_method_calls allow, simplify 8 closures ([b038062](https://github.com/air-gapped/lessence/commit/b03806251b6297b1205bf03609595431aafbe9a2))
* remove single_char_pattern allow, use char literals for splits ([0d692c9](https://github.com/air-gapped/lessence/commit/0d692c956056fd22d051f30c5687f12e1adeb782))
* remove str_split_at_newline allow, use .lines() instead ([df5130c](https://github.com/air-gapped/lessence/commit/df5130c1908bf526f5c485f39c0e887cf70343ef))
* remove uninlined_format_args allow, fix all 233 instances ([086b62f](https://github.com/air-gapped/lessence/commit/086b62f59240c254134104f9ee42b9d09dc5e81b))
* remove unreadable_literal allow, add separators to large numbers ([6572dd4](https://github.com/air-gapped/lessence/commit/6572dd44778f4577c142934ff66b693543524803))
* resolve all clippy warnings, enforce in CI ([a15316b](https://github.com/air-gapped/lessence/commit/a15316b1858f3a5cef9b8b36eaa21ea71260f5ca))
* use GitHub App token for release-please, fix deny.toml schema ([c676a45](https://github.com/air-gapped/lessence/commit/c676a45342a392001a11f2252588ee7b986990e1))
* use oauth token instead of API key for release notes ([f610a99](https://github.com/air-gapped/lessence/commit/f610a9967c5401e8650f6427e10b53a109f8e491))


### Performance Improvements

* compile ANSI regex once via LazyLock instead of per-call ([9f7f8ee](https://github.com/air-gapped/lessence/commit/9f7f8ee5a1b1dcb30e67cebfe862532e222ddb49))

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

## [0.1.0] - 2026-03-31

### Added
- Initial public release as `lessence`
- 16 pattern detectors (timestamp, hash, network, uuid, email, path, duration, json, kubernetes, http-status, brackets, key-value, process, quoted-string, name, decimal)
- Parallel processing via rayon
- `--essence` mode for temporal independence
- `--format markdown` output
- `--sanitize-pii` for email masking
- ReDoS protection on all regex patterns
- Security input limits (`--max-line-length`, `--max-lines`)

[Unreleased]: https://github.com/air-gapped/lessence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/air-gapped/lessence/releases/tag/v0.1.0
