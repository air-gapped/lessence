#!/usr/bin/env bash
# make distill — see docs/verification.md "scripts/distill.sh" and
# docs/distill.md "Distillation acceptance".
#
# For each examples/originals/*.log: run
# --distill --anonymize, grep the output against the forbid list, and
# (only when a .accept file exists, or BLESS=1) write/check the .golden
# inventory. Non-zero exit names the failing corpus.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCRUB_VOCAB="${SCRUB_VOCAB:-$HOME/security/lessence/vocab.txt}"
SCRUB_FORBID="${SCRUB_FORBID:-$HOME/security/lessence/forbid.txt}"
BIN="target/release/lessence"
DIST_DIR="examples/distilled"
mkdir -p "$DIST_DIR"

[ -f "$SCRUB_VOCAB" ] || { echo "vocab file missing: $SCRUB_VOCAB" >&2; exit 1; }
[ -f "$SCRUB_FORBID" ] || { echo "forbid file missing: $SCRUB_FORBID" >&2; exit 1; }
forbid_regex="$(cat "$SCRUB_FORBID")"

echo "Building release binary..." >&2
cargo build --release >/dev/null

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

golden_of() {
    # $1 = distilled log path -> writes count<TAB>template sorted to stdout
    local f="$1"
    if [ "$have_jq" -eq 1 ]; then
        "$BIN" --explain --threads 1 "$f" | jq -r 'select(.type=="group") | "\(.count)\t\(.normalized)"' | sort
    else
        "$BIN" --explain --threads 1 "$f" | python3 -c '
import json, sys
rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    o = json.loads(line)
    if o.get("type") != "group":
        continue
    rows.append(f"{o[\"count\"]}\t{o[\"normalized\"]}")
rows.sort()
print("\n".join(rows))
'
    fi
}

fail() {
    echo "distill FAILED: $1" >&2
    exit "${2:-1}"
}

shopt -s nullglob
for f in examples/originals/*.log; do
    name="$(basename "$f" .log)"
    if [ -n "${CORPUS:-}" ] && [ "$name" != "$CORPUS" ]; then
        continue
    fi
    dist_log="$DIST_DIR/${name}.log"
    accept_file="$DIST_DIR/${name}.accept"
    golden_file="$DIST_DIR/${name}.golden"

    lines_in="$(wc -l < "$f")"

    set +e
    "$BIN" --distill --anonymize --seed 1 --anonymize-words "$SCRUB_VOCAB" "$f" > "$dist_log"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        rm -f "$dist_log"
        fail "$name (--distill exited $rc)"
    fi

    if grep -qE "$forbid_regex" "$dist_log"; then
        rm -f "$dist_log"
        fail "$name (forbidden string found in distilled output)"
    fi

    lines_out="$(wc -l < "$dist_log")"

    rejected=0
    [ -f "$accept_file" ] && grep -q '^verdict: reject$' "$accept_file" && rejected=1

    accepted=0
    if [ "$rejected" -eq 0 ]; then
        if [ -n "${BLESS:-}" ]; then
            accepted=1
        elif [ -f "$accept_file" ] && grep -q '^verdict: accept$' "$accept_file"; then
            accepted=1
        fi
    fi

    golden_status="no-accept"
    groups="?"
    if [ "$rejected" -eq 1 ]; then
        golden_status="rejected"
        if [ -f "$golden_file" ]; then
            rm -f "$golden_file"
        fi
    fi
    if [ "$accepted" -eq 1 ]; then
        fresh="$(mktemp)"
        golden_of "$dist_log" > "$fresh"
        groups="$(wc -l < "$fresh")"
        if [ -f "$golden_file" ] && [ -z "${BLESS:-}" ]; then
            if diff -u "$golden_file" "$fresh" > /tmp/distill-golden-diff.$$; then
                golden_status="kept"
            else
                golden_status="changed"
                cat /tmp/distill-golden-diff.$$ >&2
                rm -f /tmp/distill-golden-diff.$$
                echo "$name  ${lines_in} -> ${lines_out}  groups=${groups}  golden:${golden_status}"
                rm -f "$fresh"
                exit 1
            fi
            rm -f /tmp/distill-golden-diff.$$
        else
            if [ -f "$golden_file" ]; then
                diff -u "$golden_file" "$fresh" >&2 || true
                golden_status="changed"
            else
                golden_status="written"
            fi
            cp "$fresh" "$golden_file"
        fi
        rm -f "$fresh"
    fi

    echo "$name  ${lines_in} -> ${lines_out}  groups=${groups}  golden:${golden_status}"
done
shopt -u nullglob
