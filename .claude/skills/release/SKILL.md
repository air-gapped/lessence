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

### Is the release PR up to date with main?

The PR is a *projection* of main: every push reruns `release.yml`, which
rewrites the PR's version and changelog from the conventional commits since
the last tag. It is current iff the latest `release.yml` run succeeded on
main's HEAD:

```bash
[ "$(gh run list --workflow release.yml --limit 1 --json headSha,conclusion \
      -q 'select(.[0].conclusion == "success") | .[0].headSha')" \
  = "$(git rev-parse origin/main)" ] \
  && echo "release PR is current" || echo "NOT current — run pending/failed, or stale-PR bug (see Troubleshooting)"
```

Never edit the PR or Cargo.toml version by hand — push a commit and let it
regenerate. `docs:`/`chore:`/`test:` pushes still rerun the workflow (keeping
the PR's base fresh) but add nothing to the changelog.

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

## Straggler Commits After the Release PR Merged

While the release is still a **draft**, the tag is movable — no binaries
exist, crates.io is untouched. To pull post-merge commits (typically docs
that should ship with the release) into it:

```bash
git tag -f vX.Y.Z $(git rev-parse origin/main)
git push origin vX.Y.Z --force
gh release edit vX.Y.Z --draft --target $(git rev-parse origin/main)
```

Only safe for changelog-hidden commit types (docs/chore/test) — a fix/feat
straggler belongs in the next release, since the changelog was generated at
merge. NEVER move a published release's tag.

## Pre-release Verification

Before merging a release PR, verify code AND documentation surfaces.
**Order matters: crates.io packages the README at the tag** — a stale README
caught after publishing is stuck on crates.io until the next release.

```bash
make ci              # fmt + clippy + doc + build + test + deny
make release-check   # scripts/release-surface-check.sh — README numbers,
                     # skill sources.md freshness, jq recipe shape, marker sanity
```

`release-check` is mechanical but not complete — also eyeball:

- README headline example: pasted from a real run of THIS version?
- README flag table vs `lessence --help` (semantics, not just spelling)
- `.claude/skills/lessence/` claims + `sources.md` stamps cover every
  user-facing change in the changelog
- Release-notes Highlights cover every changelog entry that a user would
  notice (style: memory `lessence-release-notes-style`)
