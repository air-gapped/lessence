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

Doc/skill drift is **enforced, not checked by hand**:

- `cargo test` includes the doc-contract suite (`tests/doc_contract.rs`) — README
  gen: regions, flag coverage, rollup-cap sanity, link integrity. Regenerate
  stale regions with `make docs`. Runs in `make ci` and the required
  `test (ubuntu-latest)` check.
- The release PR cannot merge until `test (ubuntu-latest)` AND `release-gate`
  are green. `release-gate` fails if any feat/fix/perf commit touching src/
  postdates the skill's `verified-at:` sha in sources.md — follow its error
  annotation verbatim: commit the re-verification to MAIN (never the PR
  branch), then **re-run the failed check** with
  `gh run rerun <run-id> --failed` (or "Re-run jobs" in the UI). The job
  checks out current main, so the rerun passes. A docs-only commit does NOT
  refresh the release PR — release-please only force-pushes the PR branch
  when the generated changelog/version changes — so the check will never
  re-trigger on its own. Never use `gh pr merge --admin` to get past it.
- Publishing is also guarded at the tag: `release-build.yml` refuses to
  `cargo publish` unless the tag commit is an ancestor of main and the
  doc-contract suite passes at that commit — a tag pushed from a side branch
  cannot reach crates.io.
- Only remaining eyeball item: release-notes Highlights cover every
  user-noticeable changelog entry.
