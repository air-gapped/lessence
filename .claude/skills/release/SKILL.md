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

# 3. Bump the version and write the changelog section BY HAND.
#    Users read this. Say what changed for them, not what moved in the code.
$EDITOR Cargo.toml CHANGELOG.md
cargo build --release        # refresh Cargo.lock
make gate                    # the pre-commit hook wants it for Cargo.toml
git commit -am "chore: release X.Y.Z"

# 4. Refresh the README compression table AFTER the bump: its freshness
#    check compares src/ and Cargo.toml, so a table measured before the
#    bump is stale by definition. Needs a release binary built from HEAD.
cargo build --release
./scripts/readme-compression.sh --write vX.Y.Z
git commit -am "docs: README compression table measured for vX.Y.Z"
#    And move `verified-at:` in .claude/skills/lessence/references/sources.md
#    to HEAD once the skill has been re-read against every user-facing
#    src/ commit since the old sha.

# 5. The gate. This is what decides "ready" — not judgement.
make release-check           # ~20 min

# 6. Dry run of the release on every platform: the whole test suite, the
#    build, the smoke tests and the packaging, natively on macOS and
#    Windows and under qemu for aarch64. Nothing is tagged or published.
#    Manual only — nothing builds on push.
git push origin main
gh workflow run release-build.yml --ref main
gh run watch "$(gh run list --workflow release-build.yml --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status

# 7. The release, only after both passed. The same jobs run again, and only
#    if every one is green does the workflow create the tag and the GitHub
#    release at the tested commit (notes: the version's CHANGELOG.md
#    section), and only after that publish the crate. A perf delta over the
#    gate's threshold is the owner's call; once accepted, that gate line is
#    the one FAIL release-check may carry, and the handoff states it.
gh workflow run release-build.yml --ref main -f tag=vX.Y.Z
gh run watch "$(gh run list --workflow release-build.yml --limit 1 --json databaseId -q '.[0].databaseId')" --exit-status
```

Never tag by hand and never `gh release create` by hand: the workflow
creates both, after the matrix. That order is the fix for 0.8.0, which was
released first and built second, and whose crate reached crates.io while
macOS was failing to compile (yanked). It follows astral-sh/uv and ruff:
a manual workflow whose default input is a dry run, `release` needing
every build, `publish-crate` needing `release`.

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
| release targets | `cargo check --release --target` for every shipped target: a Linux-only API is caught here, not on the release runners |

The skill check used to be a GitHub check on the release-please PR branch. With
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

- **A build or test fails in the release run**: nothing is public — the tag
  is created only after the whole matrix passes. Fix on main, push, and run
  the release again.
- **The crate did not publish** (release created, `publish-crate` red):
  `gh run rerun <run-id> --failed` retries only that job. crates.io
  publishes are immutable; never publish from a laptop to work around it.
- **A published version is broken**: yank it on crates.io (the owner holds
  the login), turn its GitHub release back into a draft, and supersede it —
  a yanked version can never be reused.

## History worth keeping

Two releases, `v0.6.0` and `v0.7.0`, were tagged and drafted but never
published, while users stayed on `v0.5.0`. That is the failure this process
exists to prevent: the drafts were deleted, the tags kept (they are true —
those commits were tagged), and the next release supersedes them.
