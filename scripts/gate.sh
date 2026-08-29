#!/usr/bin/env bash
# make gate — see docs/verification.md "scripts/gate.sh".
#
# Exit 0 = PASS, 1 = FAIL, 2 = cannot run (says why).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE_BASE="${GATE_BASE:-HEAD}"
GATE_PERF_MAX="${GATE_PERF_MAX:-1.0}"
GATE_DIR="target/gate"
mkdir -p "$GATE_DIR"

die2() {
    echo "CANNOT RUN: $1" >&2
    exit 2
}

# ── 1. Preconditions ───────────────────────────────────────────────────────

shopt -s nullglob
distilled_corpora=()
missing_golden=()
for f in examples/distilled/*.log; do
    name="$(basename "$f" .log)"
    if [ -f "examples/distilled/${name}.golden" ]; then
        distilled_corpora+=("$name")
    else
        missing_golden+=("$name")
    fi
done
shopt -u nullglob

if [ "${#distilled_corpora[@]}" -eq 0 ]; then
    if [ "${#missing_golden[@]}" -gt 0 ]; then
        die2 "no examples/distilled/*.log has a .golden beside it (missing golden: ${missing_golden[*]})"
    fi
    die2 "no examples/distilled/*.log found — run 'make distill' first"
fi

paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 999)"
if [ "$paranoid" -gt 2 ]; then
    die2 "perf_event_paranoid=$paranoid (need <=2) — 'perf stat -e instructions:u' won't work unprivileged"
fi
if ! perf stat -e instructions:u -- true >/dev/null 2>/tmp/gate-perf-check.$$; then
    err="$(cat /tmp/gate-perf-check.$$)"
    rm -f /tmp/gate-perf-check.$$
    die2 "perf stat -e instructions:u does not work unprivileged: $err"
fi
rm -f /tmp/gate-perf-check.$$

# ── 2. Baseline: build GATE_BASE in a throwaway worktree, cached per commit ─

base_commit="$(git rev-parse "$GATE_BASE")"
base_worktree="$GATE_DIR/base-${base_commit}-wt"
base_dir="$GATE_DIR/base-${base_commit}"
base_bin="$base_dir/lessence"

if [ ! -x "$base_bin" ]; then
    echo "Building baseline ($GATE_BASE = $base_commit)..." >&2
    if [ ! -d "$base_worktree" ]; then
        git worktree add --detach "$base_worktree" "$base_commit" >/dev/null
    fi
    ( cd "$base_worktree" && cargo build --release >/dev/null )
    mkdir -p "$base_dir"
    cp "$base_worktree/target/release/lessence" "$base_bin"
fi

# ── 3. New: build the working tree (uncommitted changes included) ──────────

echo "Building working tree..." >&2
cargo build --release >/dev/null
new_bin="target/release/lessence"

base_sha="$(sha256sum "$base_bin" | awk '{print $1}')"
new_sha="$(sha256sum "$new_bin" | awk '{print $1}')"

# `cargo build --release` is not byte-reproducible across build directories
# (the baseline is built in a throwaway worktree at a different path — an
# ELF build-id or similar differs even for identical source), so the sha256
# equality the spec names is a bonus fast-path, not the real test. The real
# test is git: does anything that could change the binary's behaviour — src/
# or Cargo.lock, including uncommitted changes — actually differ from
# GATE_BASE?
src_diff="$(git diff "$base_commit" -- src Cargo.lock)"
if [ "$base_sha" = "$new_sha" ] || [ -z "$src_diff" ]; then
    die2 "nothing to compare — src/ and Cargo.lock are identical to the $GATE_BASE baseline"
fi

# ── 4. Cases: new ##CASE headers vs the baseline commit's fixture ──────────

fixture="tests/fixtures/fold_regressions.log"
base_fixture="$GATE_DIR/base-${base_commit}-fixture.log"
git show "${base_commit}:${fixture}" > "$base_fixture" 2>/dev/null || : > "$base_fixture"


# Header TEXT repeats across unrelated cases (many share "groups=1"), so set
# membership over-forgives: it would call an appended duplicate header
# "already known". Diff the two ordered sequences instead — a positional
# comparison distinguishes "this many groups=1 headers now" from "this many
# before", and reports the tail as added. Only append ('a') hunks are read;
# a case inserted mid-file or an edited/removed header is the commit-msg
# hook's job (truth-layer check), not gate.sh's.
new_headers_numbered="$GATE_DIR/new-headers-numbered.txt"
grep -n '^##CASE ' "$fixture" > "$new_headers_numbered" || : > "$new_headers_numbered"
new_headers_text="$GATE_DIR/new-headers-text.txt"
sed -E 's/^[0-9]+://' "$new_headers_numbered" > "$new_headers_text"
base_headers_text_file="$GATE_DIR/base-headers-text.txt"
grep '^##CASE ' "$base_fixture" > "$base_headers_text_file" || : > "$base_headers_text_file"

headers_diff="$GATE_DIR/headers.diff"
diff "$base_headers_text_file" "$new_headers_text" > "$headers_diff" || true

new_case_lines=()
while IFS= read -r idx; do
    [ -z "$idx" ] && continue
    entry="$(sed -n "${idx}p" "$new_headers_numbered")"
    lineno="${entry%%:*}"
    header="${entry#*:}"
    new_case_lines+=("$lineno:$header")
done < <(awk '
/^[0-9]+(,[0-9]+)?a[0-9]+(,[0-9]+)?$/ {
    split($0, parts, "a")
    right = parts[2]
    if (right ~ /,/) { split(right, r, ","); s = r[1]; e = r[2] } else { s = right; e = right }
    for (i = s; i <= e; i++) print i
}' "$headers_diff")

n_new="${#new_case_lines[@]}"
vacuous=()

if [ "$n_new" -gt 0 ]; then
    echo "Checking $n_new new ##CASE block(s) against the baseline binary..." >&2
    total_lines="$(wc -l < "$fixture")"
    for entry in "${new_case_lines[@]}"; do
        lineno="${entry%%:*}"
        header="${entry#*:}"
        # Extract the block: from its header line to the next blank line
        # (or EOF).
        block="$(awk -v start="$lineno" 'NR>=start{print; if (NR>start && $0 ~ /^[[:space:]]*$/) exit}' "$fixture")"
        tmp_fixture="$(mktemp)"
        {
            echo "## gate.sh vacuous-case check"
            echo ""
            echo "$block"
        } > "$tmp_fixture"

        holds_on_base=0
        case "$header" in
            *" holds-on-base"*) holds_on_base=1 ;;
        esac

        set +e
        LESSENCE_BIN="$(pwd)/$base_bin" LESSENCE_FIXTURE="$tmp_fixture" \
            cargo test --release --test integration -- \
            --exact integration::test_fold_regressions::known_fold_regressions \
            >/tmp/gate-vacuous.$$ 2>&1
        rc=$?
        set -e
        rm -f "$tmp_fixture"

        if [ "$rc" -eq 0 ] && [ "$holds_on_base" -eq 0 ]; then
            vacuous+=("$header")
        fi
        rm -f /tmp/gate-vacuous.$$
    done
    unset total_lines
fi

# ── 5. Golden: --explain inventory of the NEW binary vs each corpus's .golden

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

golden_of() {
    local f="$1"
    if [ "$have_jq" -eq 1 ]; then
        "$(pwd)/$new_bin" --explain --threads 1 "$f" | jq -r 'select(.type=="group") | "\(.count)\t\(.normalized)"' | sort
    else
        "$(pwd)/$new_bin" --explain --threads 1 "$f" | python3 -c '
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

golden_diff_py='
import json, sys

def load(path):
    rows = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            count, _, template = line.partition("\t")
            rows[template] = int(count)
    return rows

old = load(sys.argv[1])
new = load(sys.argv[2])
added = sorted(t for t in new if t not in old)
removed = sorted(t for t in old if t not in new)
recounted = [
    {"template": t, "was": old[t], "now": new[t]}
    for t in sorted(old)
    if t in new and old[t] != new[t]
]
# The row and its counts on two lines: the caller reads files, never argv.
# A golden diff runs to hundreds of KB and a single argv argument is capped
# near 128 KB, so passing the diff back in as an argument crashes the gate
# exactly when the change is large enough to matter.
print(json.dumps({"corpus": sys.argv[3], "added": added,
                  "removed": removed, "recounted": recounted}))
print(len(added), len(removed), len(recounted))
'

golden_json_rows=()
golden_table_rows=()
for name in "${distilled_corpora[@]}"; do
    fresh="$(mktemp)"
    golden_of "examples/distilled/${name}.log" > "$fresh"
    golden_file="examples/distilled/${name}.golden"

    diff_result="$(python3 -c "$golden_diff_py" "$golden_file" "$fresh" "$name")"
    golden_json_rows+=("$(printf '%s' "$diff_result" | head -1)")
    read -r n_added n_removed n_recounted <<< "$(printf '%s' "$diff_result" | tail -1)"

    if [ "$n_added" -gt 0 ] || [ "$n_removed" -gt 0 ] || [ "$n_recounted" -gt 0 ]; then
        golden_table_rows+=("$(printf '%-24s added=%s removed=%s recounted=%s' "$name" "$n_added" "$n_removed" "$n_recounted")")
    fi
    rm -f "$fresh"
done

# ── 6. Perf: instructions:u on distilled kubelet, pinned, two rounds, min ──

GATE_CPU="${GATE_CPU:-$(cut -d- -f1 /sys/devices/cpu_core/cpus 2>/dev/null || echo 0)}"
PERF_CORPUS="examples/distilled/kubelet.log"
[ -f "$PERF_CORPUS" ] || die2 "$PERF_CORPUS missing — run 'make distill' first"

perf_instructions() {
    local bin="$1" min="" prev="" spread="0"
    local n_rounds=2
    local i=0
    while [ "$i" -lt "$n_rounds" ]; do
        i=$((i + 1))
        local raw
        raw="$(LC_ALL=C taskset -c "$GATE_CPU" perf stat -e instructions:u,task-clock -x, -- \
            "$bin" --threads 1 -q "$PERF_CORPUS" 2>&1 >/dev/null)"
        local sum
        sum="$(awk -F, '/instructions\/u/ { if ($1 ~ /^[0-9]+$/) s+=$1 } END { print s+0 }' <<<"$raw")"
        if [ -z "$min" ] || [ "$sum" -lt "$min" ]; then
            min="$sum"
        fi
        if [ -n "$prev" ]; then
            spread="$(awk -v a="$prev" -v b="$sum" 'BEGIN { d=a-b; if (d<0) d=-d; if (a==0){print 0} else {printf "%.4f", d/a*100} }')"
        fi
        prev="$sum"
    done
    # Third round if the two rounds differ by more than 0.3%.
    if awk -v s="$spread" 'BEGIN { exit !(s>0.3) }'; then
        local raw sum
        raw="$(LC_ALL=C taskset -c "$GATE_CPU" perf stat -e instructions:u,task-clock -x, -- \
            "$bin" --threads 1 -q "$PERF_CORPUS" 2>&1 >/dev/null)"
        sum="$(awk -F, '/instructions\/u/ { if ($1 ~ /^[0-9]+$/) s+=$1 } END { print s+0 }' <<<"$raw")"
        if [ "$sum" -lt "$min" ]; then
            min="$sum"
        fi
    fi
    echo "$min $spread"
}

echo "Measuring perf (2+ rounds each, pinned to cpu $GATE_CPU, corpus $PERF_CORPUS)..." >&2
read -r instr_base spread_base <<<"$(perf_instructions "$(pwd)/$base_bin")"
read -r instr_new spread_new <<<"$(perf_instructions "$(pwd)/$new_bin")"
spread_pct="$(awk -v a="$spread_base" -v b="$spread_new" 'BEGIN { print (a>b)?a:b }')"

delta_pct="$(awk -v b="$instr_base" -v n="$instr_new" 'BEGIN { if (b==0) { print 0 } else { printf "%.4f", (n-b)/b*100 } }')"
perf_fail=0
if awk -v d="$delta_pct" -v t="$GATE_PERF_MAX" 'BEGIN { exit !(d>t) }'; then
    perf_fail=1
fi

# ── Verdict ──────────────────────────────────────────────────────────────

verdict="PASS"
fail_reasons=()
if [ "${#vacuous[@]}" -gt 0 ]; then
    verdict="FAIL"
    fail_reasons+=("vacuous new case(s): ${vacuous[*]}")
fi
if [ "$perf_fail" -eq 1 ]; then
    verdict="FAIL"
    fail_reasons+=("perf regression: ${delta_pct}% > ${GATE_PERF_MAX}%")
fi

# ── Output: table (<=15 lines) ──────────────────────────────────────────────

echo ""
echo "gate: $GATE_BASE ($base_commit) vs working tree"
echo "cases: ${n_new} new, ${#vacuous[@]} vacuous"
echo "golden: ${#distilled_corpora[@]} corpora, ${#golden_table_rows[@]} changed"
for row in "${golden_table_rows[@]}"; do
    echo "  $row"
done
printf "perf(%s): instructions:u base=%s new=%s delta=%s%% (max %s%%) spread=%s%%\n" \
    "$PERF_CORPUS" "$instr_base" "$instr_new" "$delta_pct" "$GATE_PERF_MAX" "$spread_pct"
echo "verdict: $verdict"
for r in "${fail_reasons[@]:-}"; do
    [ -n "$r" ] && echo "  - $r"
done

# ── gate.json ────────────────────────────────────────────────────────────

staged_diff_sha256="$( (git diff --cached; git diff) | sha256sum | awk '{print $1}')"
rustc_version="$(rustc --version)"
git_head="$(git rev-parse HEAD)"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

golden_json="$(IFS=,; echo "${golden_json_rows[*]:-}")"
vacuous_json="$(printf '"%s",' "${vacuous[@]:-}" | sed 's/,$//')"
cases_new_failing_on_base=$((n_new - ${#vacuous[@]}))

cat > "$GATE_DIR/gate.json" <<JSON
{
  "time": "${now}",
  "git_head": "${git_head}",
  "staged_diff_sha256": "${staged_diff_sha256}",
  "base": {"ref": "${GATE_BASE}", "commit": "${base_commit}", "sha256": "${base_sha}"},
  "new": {"sha256": "${new_sha}", "rustc": "${rustc_version}"},
  "cases": {"new": ${n_new}, "new_failing_on_base": ${cases_new_failing_on_base}, "vacuous": [${vacuous_json}]},
  "golden": [${golden_json}],
  "perf": {"cpu": ${GATE_CPU}, "instructions_base": ${instr_base}, "instructions_new": ${instr_new},
           "spread_pct": ${spread_pct}, "delta_pct": ${delta_pct}, "threshold_pct": ${GATE_PERF_MAX}},
  "verdict": "${verdict}"
}
JSON

if [ "$verdict" = "PASS" ]; then
    exit 0
else
    exit 1
fi
