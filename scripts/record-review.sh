#!/usr/bin/env bash
# Records the fold reviewer's verdict on the change the last gate run
# measured. Only the fold-reviewer agent runs this (.claude/hooks/build-guard.sh
# refuses it from the main session); the pre-commit hook reads the result
# through scripts/check-fold-review.sh.
#
#   scripts/record-review.sh pass "<corpora checked>"
#   scripts/record-review.sh fail "<corpus>: <what folds with what>"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

verdict="${1:-}"
summary="${2:-}"
case "$verdict" in pass|fail) ;; *) echo "record-review: first argument is pass or fail" >&2; exit 2 ;; esac
[ -n "$summary" ] || { echo "record-review: second argument is a one-line summary" >&2; exit 2; }

GATE=target/gate/gate.json
[ -r "$GATE" ] || { echo "record-review: $GATE is missing. The gate has not run." >&2; exit 1; }
gate_sha=$(jq -r '.staged_diff_sha256' "$GATE")
if [ "$gate_sha" != "$(scripts/gate-diff-hash.sh)" ]; then
    echo "record-review: the tree changed since the gate ran. Nothing recorded; the gate has to run again first." >&2
    exit 1
fi

jq -n --arg sha "$gate_sha" --arg verdict "$verdict" --arg summary "$summary" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{staged_diff_sha256: $sha, verdict: $verdict, summary: $summary, time: $time}' > target/gate/review.json
echo "review recorded: $verdict"
