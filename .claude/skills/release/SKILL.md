---
name: release
description: Release workflow for lessence — version bumping, changelog updates, semantic versioning, building release binaries, tagging, publishing. Use when preparing a release, bumping versions, or updating CHANGELOG.md.
---

# Release Workflow

## Semantic Versioning

- **MAJOR (x.0.0)**: Breaking changes — removed/changed CLI flags, changed output format
- **MINOR (0.x.0)**: New features — new CLI flags, new patterns, backward compatible
- **PATCH (0.0.x)**: Bug fixes — crashes, detection errors, security patches

Current version is in `Cargo.toml` (`version = "X.Y.Z"`).

## Release Steps

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md** — move `[Unreleased]` items to a versioned section with date
3. **Build and verify**:
   ```bash
   cargo build --release
   ./target/release/lessence --version    # confirm version
   cargo test                             # all tests pass
   ```
4. **Commit**: `git commit -m "release: vX.Y.Z"`
5. **Tag**: `git tag -a vX.Y.Z -m "vX.Y.Z"`
6. **Push**: `git push && git push --tags`

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/):

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description

### Removed
- Removed feature description
```

## Breaking Changes

For major version bumps:
- Bump version at the START of the work (signals intent)
- Document migration path in CHANGELOG
- Update README with new usage examples

## Pre-release Checklist

- [ ] Version updated in Cargo.toml
- [ ] CHANGELOG.md updated
- [ ] `cargo build --release` succeeds with 0 warnings
- [ ] `cargo test` passes
- [ ] README.md reflects current features
- [ ] Binary runs: `./target/release/lessence --version`
