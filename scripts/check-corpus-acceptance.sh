#!/usr/bin/env bash
# A distilled corpus has a golden only after its acceptance is written down
# (docs/verification.md, "Distillation acceptance"). For every
# examples/distilled/<name>.golden this requires <name>.accept with either
#
#   verdict: accept
#
# or a rejection that an open issue owns:
#
#   verdict: reject
#   tracked: lessence-xxxx
#
# The corpora are gitignored, so a checkout without them has nothing to
# check and passes; the gates that read corpora fail there on their own.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIST=examples/distilled
ISSUES=.beads/issues.jsonl

shopt -s nullglob
goldens=("$DIST"/*.golden)
if [ "${#goldens[@]}" -eq 0 ]; then
    echo "corpus acceptance: no distilled corpora in this checkout"
    exit 0
fi

bad=0
complain() {
    echo "corpus acceptance: $1" >&2
    bad=1
}

for golden in "${goldens[@]}"; do
    name=$(basename "$golden" .golden)
    accept="$DIST/$name.accept"
    if [ ! -r "$accept" ]; then
        complain "$name has a golden and no $accept. Study the original, write the acceptance file, then record the golden."
        continue
    fi
    verdict=$(sed -n 's/^verdict:[[:space:]]*//p' "$accept" | head -1)
    case "$verdict" in
        accept) ;;
        reject)
            bead=$(sed -n 's/^tracked:[[:space:]]*//p' "$accept" | head -1)
            if [ -z "$bead" ]; then
                complain "$name is rejected and names no issue. Add 'tracked: <issue id>' to $accept, or remove the corpus."
            elif ! jq -e --arg id "$bead" 'select(.id == $id and .status != "closed")' "$ISSUES" >/dev/null 2>&1; then
                complain "$name is rejected and its issue $bead is closed or unknown. Accept the corpus, remove it, or name the open issue."
            fi
            ;;
        *) complain "$accept has no 'verdict: accept' or 'verdict: reject' line." ;;
    esac
done

[ "$bad" -eq 0 ] || exit 1
echo "corpus acceptance: ${#goldens[@]} corpora, each accepted or tracked"
