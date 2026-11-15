#!/usr/bin/env bash
# The code stays nearly comment-free: the number of plain comment lines
# (`//` that is not `///` or `//!`, and `/*` that is not `/**` or `/*!`) in
# src, tests and benches may only shrink. The budget is in
# tests/fixtures/comment-budget.txt; this runs in `make ci`.
#
#   scripts/check-comment-budget.sh           exit 1 when a count differs from the budget
#   scripts/check-comment-budget.sh --record  write the current counts to the budget file
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUDGET=tests/fixtures/comment-budget.txt
DIRS=(src tests benches)
RE='^[[:space:]]*(//([^/!]|$)|/\*([^*!]|$))'

count() {
    local n
    n=$(find "$1" -name '*.rs' -type f -print0 | xargs -0 -r grep -hE "$RE" | wc -l)
    echo "$n"
}

declare -A now
for d in "${DIRS[@]}"; do now[$d]=$(count "$d"); done

line() { echo "${DIRS[0]} ${now[src]}"; echo "tests ${now[tests]}"; echo "benches ${now[benches]}"; }

if [[ "${1:-}" == "--record" ]]; then
    line > "$BUDGET"
    echo "comment budget recorded: src ${now[src]}, tests ${now[tests]}, benches ${now[benches]}"
    exit 0
fi

declare -A budget
while read -r name n; do budget[$name]=$n; done < "$BUDGET"

fail=0
for d in "${DIRS[@]}"; do
    have=${now[$d]}
    want=${budget[$d]:?missing $d in $BUDGET}
    if (( have > want )); then
        fail=1
        echo "comment budget: $d has $have plain comment lines, the budget is $want" >&2
        added=$(git diff -U0 HEAD -- "$d" | awk '
            /^\+\+\+ b\// { file = substr($0, 7); next }
            /^@@/ { match($0, /\+[0-9]+/); ln = substr($0, RSTART + 1, RLENGTH - 1) + 0; next }
            /^\+/ { print file ":" ln ": " substr($0, 2); ln++ }
        ' | grep -E "^[^:]+:[0-9]+: ${RE#^}" || true)
        [[ -n "$added" ]] && echo "$added" >&2
        echo "Say it in a name, a type, a constant or an assertion message. A comment that states a fact from outside the code (a spec, an upstream bug) may stay by raising the number in $BUDGET in the same commit." >&2
    elif (( have < want )); then
        fail=1
        echo "comment budget: $d has $have plain comment lines, the budget is $want. Lower the budget so it only ratchets down: in $BUDGET set the line to" >&2
        echo "$d $have" >&2
    fi
done
(( fail )) && exit 1
echo "comment budget: src ${now[src]}, tests ${now[tests]}, benches ${now[benches]}"
