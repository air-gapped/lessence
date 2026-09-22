---
name: release
description: >-
  Release workflow for lessence — the agent runs the whole release: version
  bump, changelog section, release-check, tag, push, publish. Use when
  preparing a release, checking whether one is ready, fixing a release that
  went wrong, or understanding how versions are managed.
---

# Release Workflow

**The agent runs the release end to end.** There is no bot. release-please
was removed on 2026-09-22 after it produced two tagged-but-unpublished
versions and a stale changelog; nothing opens a PR against this repo any
more.

A release is a tag plus a published GitHub release. Pushing `main` does
**not** start one — push freely, but remember the repo is public and
everything pushed is visible.

## The sequence

Nothing here is optional and the order matters: the tag is a public claim
and must never point at a commit that failed a check.

```bash
# 1. Everything intended for the release is committed and on main.
git status --short          # clean
git log --oneline <last-tag>..HEAD

# 2. Decide the version from what is IN that range, not from habit.
#    feat: -> minor. fix:/perf: -> patch. A changed or removed --format json
#    field, flag or exit code is BREAKING: minor while 0.x, major after 1.0.

# 3. Refresh the README compression table (it is stamped with a commit, and
#    release-check refuses a stale one). Needs a clean src/ and a release
#    binary built from HEAD.
cargo build --release
./scripts/readme-compression.sh --write vX.Y.Z
git commit -am "docs: README compression table measured for vX.Y.Z"

# 4. Bump the version and write the changelog section BY HAND.
#    Users read this. Say what changed for them, not what moved in the code.
$EDITOR Cargo.toml CHANGELOG.md
cargo build --release        # refresh Cargo.lock
git commit -am "chore: release X.Y.Z"

# 5. The gate. This is what decides "ready" — not judgement.
make release-check           # ~20 min

# 6. Only if it passed: tag, push, publish.
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
gh release create vX.Y.Z --title vX.Y.Z --notes-file <notes>
```

Step 6's `gh release create` publishes immediately, which fires
`release-build.yml` (`on: release: [released]`). That workflow refuses a tag
that is not on `main`, re-runs the doc contract at the tag, publishes the
crate, and builds and attaches the musl binaries.

## What release-check proves

`scripts/release-check.sh`, writing `target/gate/release.json`:

| Check | Meaning |
|---|---|
| gate vs the last **published** release | not the last tag — a tag can exist with no release behind it, and comparing to it hides what the upgrade costs |
| mutants `--in-diff` | the tests kill the mutants the diff introduced |
| `make ci` | fmt, clippy, doc, tests, deny |
| slow tests | the wall-clock profile the default profile excludes |
| README compression table | generated at a commit whose `src/` equals today's |
| agent skill re-verified | `sources.md`'s `verified-at:` sha covers every user-facing `src/` commit |

The last one used to be a GitHub check on the release-please PR branch. With
no PR to hang it on it moved into `release-check`, because a check that only
fires on a branch nobody creates is a check that never runs.

**Perf against the last published release is separate** and is not in
`release-check`: see `CLAUDE.local.md` for the script, and state the
cumulative number in the handoff.

## Version rules

- `Cargo.toml` is edited by hand now. Nothing rewrites it.
- The tag is `vX.Y.Z`; `Cargo.toml` carries `X.Y.Z`.
- **The version string comes from the tag**, via `git describe`. A tag with
  no release behind it makes every later build claim that version — which is
  how builds nine commits past `v0.7.0` came to report `0.7.0`.
- A tag is public the moment it is pushed. Do not push one speculatively.

## If something goes wrong

- **Binaries missing from a published release**:
  `gh workflow run release-build.yml -f tag=vX.Y.Z` rebuilds and reattaches.
- **Tag pushed by mistake, nothing published**: delete it on both sides
  (`git tag -d`, `git push --delete origin`) before anyone fetches it. Once a
  release is published, supersede rather than delete — crates.io publishes
  are immutable.
- **Release created but the crate did not publish**: check `publish-crate` in
  the run; its ancestry guard refuses a tag that is not on `main`.

## History worth keeping

Two releases, `v0.6.0` and `v0.7.0`, were tagged and drafted but never
published, while users stayed on `v0.5.0`. That is the failure this process
exists to prevent: the drafts were deleted, the tags kept (they are true —
those commits were tagged), and the next release supersedes them.
