---
name: release
description: >-
  Release workflow for lessence — release-please automation, conventional
  commits, version bumping, changelog, binary publishing. Use when preparing
  a release, checking release status, fixing release issues, or understanding
  how versions are managed.
---

# Release Workflow

Releases are **fully automated** via release-please. No manual version bumping,
changelog editing, or tagging. The workflow is: write conventional commits →
merge to main → release-please does the rest.

## How It Works

1. **Conventional commits on main** trigger release-please (`release.yml`)
2. Release-please opens/updates a **release PR** with version bump + changelog
3. **Merging the release PR** creates a GitHub release + git tag
4. The release triggers:
   - `cargo publish` to crates.io
   - Binary builds for 5 targets (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows)
   - SHA256 checksums uploaded to the GitHub release

## Commit Types That Drive Releases

From CLAUDE.md — the commit type controls what appears in the changelog:

- `feat:` → **minor** version bump, appears in changelog
- `fix:` → **patch** version bump, appears in changelog
- `perf:` → **patch** version bump, appears in changelog
- `feat!:` or `BREAKING CHANGE:` footer → **major** version bump
- `test:`, `refactor:`, `style:`, `chore:`, `docs:`, `ci:`, `build:` → no release, hidden from changelog

The first line of the commit message becomes the changelog entry. Write it
for users: "add --fit flag for screen-sized output" not "implement fit_budget
in folder.rs".

## Checking Release Status

```bash
# See if a release PR is open
gh pr list --label "autorelease: pending"

# Check the latest release
gh release list --limit 1

# Current version in Cargo.toml
grep '^version' Cargo.toml
```

## Configuration

- **PR management**: `.github/workflows/release.yml` — runs on push to main, only manages the release PR
- **Build + publish**: `.github/workflows/release-build.yml` — triggers on `release: published` event only
- **Release-please**: uses defaults (auto-detects Rust from Cargo.toml, no config file)
- **Auth**: GitHub App token via `RELEASE_BOT_APP_ID` / `RELEASE_BOT_PRIVATE_KEY` secrets
- **Binary builds**: `taiki-e/upload-rust-binary-action` with musl for Linux

## Troubleshooting

- **PR has stale/wrong changelog** (includes old commits, wrong version): close the PR, delete its branch (`gh pr close N --delete-branch`), push a commit to retrigger. This is a known release-please bug that recurs.
- **Release PR not appearing**: check that commits use conventional format and include `feat:` or `fix:`
- **Version mismatch**: release-please manages `Cargo.toml` version — do not edit it manually
- **Failed binary build**: check the matrix job for the failing target in Actions
- **Crate publish failed**: uses OIDC via `crates-io-auth-action`, not a token secret — check the action version and crates.io trusted publisher config

## Pre-release Verification

Before merging a release PR, verify:

```bash
cargo build --release
cargo test
cargo clippy
./target/release/lessence --version
```
