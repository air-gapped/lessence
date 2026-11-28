#!/usr/bin/env bash
# Re-record the golden of every corpus the last gate run reports as changed,
# with the binary that gate run built. Read the gate's golden diff first:
# this makes any output "correct".
#
#   scripts/record-goldens.sh            the corpora target/gate/gate.json lists as changed
#   scripts/record-goldens.sh <name>...  these corpora, by name
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN=target/release/lessence
GATE=target/gate/gate.json
DIST=examples/distilled

[ -x "$BIN" ] || { echo "record-goldens: $BIN is missing. Run the gate first." >&2; exit 1; }

if [ "$#" -gt 0 ]; then
    names=("$@")
else
    [ -r "$GATE" ] || { echo "record-goldens: $GATE is missing. Run the gate first." >&2; exit 1; }
    mapfile -t names < <(jq -r '.golden[] | select((.added + .removed + .recounted) | length > 0) | .corpus' "$GATE")
fi

if [ "${#names[@]}" -eq 0 ]; then
    echo "record-goldens: the gate reports no changed golden"
    exit 0
fi

for name in "${names[@]}"; do
    log="$DIST/$name.log"
    [ -r "$log" ] || { echo "record-goldens: $log is missing" >&2; exit 1; }
    # The golden is replaced only by a whole inventory: a failing run leaves
    # the old one in place.
    tmp=$(mktemp "$DIST/.$name.golden.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    "$BIN" --explain --threads 1 "$log" \
        | jq -r 'select(.type=="group") | "\(.count)\t\(.normalized)"' \
        | LC_ALL=C sort > "$tmp"
    mv -f "$tmp" "$DIST/$name.golden"
    trap - EXIT
    echo "recorded $name ($(wc -l < "$DIST/$name.golden") templates)"
done
