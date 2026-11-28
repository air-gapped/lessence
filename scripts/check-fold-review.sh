#!/usr/bin/env bash
# A change whose gate run changed any golden is committed only after the
# fold-reviewer agent (.claude/agents/fold-reviewer.md) has read that golden
# diff and recorded "pass" for exactly this change. Called by the pre-commit
# hook after its gate check, with no arguments: the canonical paths. The
# self-tests pass a gate report and a review path as arguments; the
# environment never chooses them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE="${1:-target/gate/gate.json}"
REVIEW="${2:-target/gate/review.json}"

changed=$(jq '[.golden[]? | select((.added + .removed + .recounted) | length > 0)] | length' "$GATE")
if [ "$changed" -eq 0 ]; then
    echo "fold review: no golden changed, none needed"
    exit 0
fi

how="Spawn the fold-reviewer agent (Agent tool, subagent_type fold-reviewer) with no conclusion of your own; it records the verdict."
if [ ! -r "$REVIEW" ]; then
    echo "fold review: the gate changed $changed golden(s) and no review is recorded. $how" >&2
    exit 1
fi
if [ "$(jq -r '.staged_diff_sha256' "$REVIEW")" != "$(jq -r '.staged_diff_sha256' "$GATE")" ]; then
    echo "fold review: the recorded review is for a different change. $how" >&2
    exit 1
fi
if [ "$(jq -r '.verdict' "$REVIEW")" != "pass" ]; then
    echo "fold review: the reviewer found a defect: $(jq -r '.summary' "$REVIEW"). Fix it, run the gate again, and have it reviewed again." >&2
    exit 1
fi
echo "fold review: pass ($changed golden(s) changed)"
