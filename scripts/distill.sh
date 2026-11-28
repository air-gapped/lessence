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

SCRUB_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/lessence"
SCRUB_VOCAB="${SCRUB_VOCAB:-$SCRUB_DIR/scrub-vocab.txt}"
SCRUB_FORBID="${SCRUB_FORBID:-$SCRUB_DIR/scrub-forbid.txt}"
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
        "$BIN" --explain --threads 1 "$f" | jq -r 'select(.type=="group") | "\(.count)\t\(.normalized)"' | LC_ALL=C sort
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
    rows.append("{}\t{}".format(o["count"], o["normalized"]))
rows.sort()
for row in rows:
    print(row)
'
    fi
}

golden_diff() {
    # Inventories are multisets of rows, independent of the locale that
    # wrote them. Keep duplicates: an extra group must still be visible.
    diff -u --label "$1" --label "$1 (current)" \
        <(LC_ALL=C sort "$1") <(LC_ALL=C sort "$2")
}

fail() {
    echo "distill FAILED: $1" >&2
    exit "${2:-1}"
}

pending=""
trap 'if [ -n "$pending" ]; then rm -f "$pending"; fi' EXIT

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

    echo "distill rate comparison: $name" >&2

    # The output is written and scanned under a private name in the same
    # directory and takes its final name only after the scan passes; a
    # failing or interrupted run leaves the earlier distilled log as it was.
    pending="$(mktemp "$DIST_DIR/.$name.log.XXXXXX")"
    set +e
    "$BIN" --distill --anonymize --seed 1 --anonymize-words "$SCRUB_VOCAB" "$f" > "$pending"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        fail "$name (--distill exited $rc)"
    fi

    # grep exits 1 only when nothing matches; a match (0) or an error (2)
    # both refuse the output.
    set +e
    grep -qE -e "$forbid_regex" "$pending"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        fail "$name (forbidden string found in distilled output)"
    elif [ "$rc" -ne 1 ]; then
        fail "$name (forbid scan exited $rc)"
    fi
    # Lines added by hand at acceptance live in <name>.added, scrubbed with
    # the same --anonymize --seed 1, so their words match the new output.
    # Each one's event must be present: some new template whose literal
    # words (every <...> placeholder dropped) equal or are a subset of its
    # own, since more lines can widen a word to <VARIES>.
    added_file="$DIST_DIR/${name}.added"
    if [ -f "$added_file" ]; then
        missing="$(awk -F'\t' '
            function words(t, w,   n, i, a) { gsub(/<[^<> ]*>/, " ", t); n = split(t, a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1 }
            NR == FNR { nt++; nw = 0; delete tmp; words($2, tmp); for (k in tmp) { W[nt, ++nw] = k }; N[nt] = nw; next }
            { delete o; words($2, o); found = 0
              for (t = 1; t <= nt && !found; t++) { ok = 1; for (i = 1; i <= N[t]; i++) if (!(W[t, i] in o)) { ok = 0; break }; if (ok) found = 1 }
              if (!found) print $2 }' <(golden_of "$pending") <(golden_of "$added_file") | LC_ALL=C sort -u)"
        if [ -n "$missing" ]; then
            lost="$(printf '%s\n' "$missing" | wc -l)"
            fail "$name: $lost events missing from the new --distill output that $added_file holds (no new template shares their literal words); fix --distill or re-accept the corpus. First missing: $(printf '%s\n' "$missing" | head -3 | paste -sd'|')"
        fi
    fi
    mv -f "$pending" "$dist_log"
    pending=""

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
            diff_out="$(mktemp)"
            if golden_diff "$golden_file" "$fresh" > "$diff_out"; then
                golden_status="kept"
            else
                golden_status="changed"
                cat "$diff_out" >&2
                rm -f "$diff_out"
                echo "$name  ${lines_in} -> ${lines_out}  groups=${groups}  golden:${golden_status}"
                rm -f "$fresh"
                exit 1
            fi
            rm -f "$diff_out"
        else
            if [ -f "$golden_file" ]; then
                golden_diff "$golden_file" "$fresh" >&2 || true
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
