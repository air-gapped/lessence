#!/usr/bin/env bash
# The identity of the change `make gate` measured: a sha256 over the working
# tree's diff against HEAD. scripts/gate.sh records it in gate.json and the
# pre-commit hook recomputes it; both call this file, so they cannot drift.
#
# Staged and unstaged changes hash the same (the gate builds the working
# tree, whichever of the two a change is in), and .beads/ is left out: the
# pre-commit hook flushes and stages the bead export itself, and no gate
# reads it.
set -euo pipefail
git diff HEAD -- . ':(exclude).beads' | sha256sum | awk '{print $1}'
