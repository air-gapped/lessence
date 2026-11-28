#!/usr/bin/env bash
# The identity of the change `make gate` measured, and the pre-commit
# hook's two questions about the index. scripts/gate.sh and the hook both
# call this file, so the build-input list and the hash cannot drift.
#
#   gate-diff-hash.sh                      sha256 of the working tree's diff
#                                          against HEAD, plus untracked build
#                                          inputs (the gate builds those too)
#   gate-diff-hash.sh --staged-inputs      exit 0: the index changes a build
#                                          input; 1: it does not; 2: git error
#   gate-diff-hash.sh --index-is-tree      exit 0: every build input in the
#                                          index equals the working tree and
#                                          none is untracked; 1: they differ
#
# Staged and unstaged changes hash the same (the gate builds the working
# tree); the hook asks --index-is-tree so that what it commits is what was
# built. .beads/ is left out: the pre-commit hook flushes and stages the bead
# export itself, and no gate reads it.
set -euo pipefail

# What builds the binary: src/, the manifest and lockfile, build.rs, and the
# two skill files src/skill.rs embeds.
inputs=(src Cargo.toml Cargo.lock build.rs
    .claude/skills/lessence/SKILL.md .claude/skills/lessence/references/flags.md)

untracked() { git ls-files -z --others --exclude-standard -- "${inputs[@]}"; }

case "${1:-}" in
    --staged-inputs)
        rc=0
        git diff --cached --quiet --no-renames -- "${inputs[@]}" || rc=$?
        case "$rc" in 0) exit 1 ;; 1) exit 0 ;; *) exit 2 ;; esac
        ;;
    --index-is-tree)
        git diff --quiet -- "${inputs[@]}" || exit 1
        [ -z "$(untracked | tr -d '\0')" ] || exit 1
        exit 0
        ;;
    "") ;;
    *) echo "gate-diff-hash: unknown argument $1" >&2; exit 2 ;;
esac

{
    git diff HEAD -- . ':(exclude).beads'
    untracked | while IFS= read -r -d '' f; do
        printf 'untracked %s\n' "$f"
        sha256sum < "$f"
    done
} | sha256sum | awk '{print $1}'
