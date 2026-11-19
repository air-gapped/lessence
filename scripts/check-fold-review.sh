#!/usr/bin/env bash
# A change whose gate run changed any golden is committed only after the
# fold-reviewer agent (.claude/agents/fold-reviewer.md) has read that golden
# diff and recorded "pass" for exactly this change. Called by the pre-commit
# hook after its gate check. GATE_JSON and REVIEW_JSON override the paths
# for the self-test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE="${GATE_JSON:-target/gate/gate.json}"
REVIEW="${REVIEW_JSON:-target/gate/review.json}"

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
