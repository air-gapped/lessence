#!/usr/bin/env bash
# Baseline builds, perf sampling and the mutants verdict for scripts/gate.sh.
# Defines functions only; sourced by the gate and by scripts/gate-selftest.sh.
# Running it does nothing.

# baseline_binary <commit> <label> — prints the path of the release binary
# built from <commit>, building it first when it is not cached. Every step
# is checked: callers run this in a command substitution, where errexit does
# not reach, so a failed checkout, build or copy returns 1 and prints no path.
# Requires: GATE_DIR, base_target.
# shellcheck disable=SC2154 # base_target is the caller's
baseline_binary() {
    local commit="$1" label="$2"
    local worktree="$GATE_DIR/base-${commit}-wt" dir="$GATE_DIR/base-${commit}"
    local bin="$dir/lessence" built="$base_target/release/lessence"
    if [ ! -x "$bin" ]; then
        echo "Building baseline ($label = $commit)..." >&2
        if [ ! -d "$worktree" ]; then
            git worktree add --detach "$worktree" "$commit" >/dev/null ||
                { echo "baseline: checking out $label failed" >&2; return 1; }
        fi
        # The shared target dir holds the previous commit's binary; remove it
        # so only this build's output can be copied below.
        rm -f "$built"
        ( cd "$worktree" && CARGO_TARGET_DIR="$base_target" cargo build --release >/dev/null ) ||
            { echo "baseline: building $label failed" >&2; return 1; }
        [ -x "$built" ] || { echo "baseline: the build of $label left no binary" >&2; return 1; }
        # Copy then rename: an interrupted copy must not leave an executable
        # that the cache check above would trust.
        if ! { mkdir -p "$dir" && cp "$built" "$bin.partial" && mv "$bin.partial" "$bin"; }; then
            echo "baseline: caching the $label binary failed" >&2
            return 1
        fi
        git worktree remove --force "$worktree" ||
            { echo "baseline: removing the $label worktree failed" >&2; return 1; }
    fi
    printf '%s\n' "$bin"
}

# perf_round <binary> [args...] — prints one positive instructions:u count,
# or returns 1: a failed run, a missing or uncounted counter and a zero count
# are no measurement.
perf_round() {
    local bin="$1" raw sum
    shift
    raw="$(LC_ALL=C taskset -c "$GATE_CPU" perf stat -e instructions:u,task-clock -x, -- \
        "$bin" --threads 1 -q "$@" "$PERF_CORPUS" 2>&1 >/dev/null)" ||
        { echo "perf: measuring $bin failed: $raw" >&2; return 1; }
    sum="$(awk -F, '/instructions\/u/ && $1 ~ /^[0-9]+$/ { s+=$1; n++ } END { if (n) print s }' <<<"$raw")"
    if ! [[ "$sum" =~ ^[0-9]+$ ]] || [ "$sum" -le 0 ]; then
        echo "perf: no positive instructions:u count for $bin: $raw" >&2
        return 1
    fi
    echo "$sum"
}

# perf_instructions <binary> — prints "<min instructions:u> <spread %>" over
# two rounds, three when they differ by more than 0.3%; returns 1 when any
# round is no measurement.
# Requires: GATE_CPU, PERF_CORPUS, report_args.
perf_instructions() {
    local bin="$1" min="" prev="" spread="0" i=0 sum
    local extra=()
    mapfile -t extra < <(report_args "$bin")
    while [ "$i" -lt 2 ]; do
        i=$((i + 1))
        sum="$(perf_round "$bin" "${extra[@]}")" || return 1
        if [ -z "$min" ] || [ "$sum" -lt "$min" ]; then min="$sum"; fi
        if [ -n "$prev" ]; then
            spread="$(awk -v a="$prev" -v b="$sum" 'BEGIN { d=a-b; if (d<0) d=-d; printf "%.4f", d/a*100 }')"
        fi
        prev="$sum"
    done
    if awk -v s="$spread" 'BEGIN { exit !(s>0.3) }'; then
        sum="$(perf_round "$bin" "${extra[@]}")" || return 1
        if [ "$sum" -lt "$min" ]; then min="$sum"; fi
    fi
    echo "$min $spread"
}

# mutants_outcome <exit code> <outcomes.json> — prints "ok <total> <missed>",
# "none" (no mutable code in the diff: exit 0 and no output directory) or
# "broken <reason>". Exit 0 and 2 only; a timed-out mutant is inconclusive,
# a run with mutants needs a successful baseline, and the missed count must
# agree with the exit code (2 = some missed).
mutants_outcome() {
    local rc="$1" f="$2" total missed timeouts baseline
    case "$rc" in
        0|2) ;;
        3) echo "broken rc=3: mutants timed out, the run is inconclusive"; return ;;
        *) echo "broken rc=${rc}"; return ;;
    esac
    if ! jq -e '.outcomes | type == "array"' "$f" >/dev/null 2>&1; then
        if [ "$rc" -eq 0 ] && [ ! -e "$(dirname "$f")" ]; then echo "none"; else
            echo "broken rc=${rc}, no readable outcomes.json"; fi
        return
    fi
    if ! jq -e 'all(.outcomes[]; type == "object" and has("scenario") and (.summary | type == "string"))' "$f" >/dev/null 2>&1; then
        echo "broken rc=${rc}, outcomes.json has a malformed entry"
        return
    fi
    local m='.outcomes[] | select((.scenario|type=="object") and .scenario.Mutant)'
    total="$(jq "[$m] | length" "$f")"
    missed="$(jq "[$m | select(.summary==\"MissedMutant\")] | length" "$f")"
    timeouts="$(jq "[$m | select(.summary==\"Timeout\")] | length" "$f")"
    baseline="$(jq '[.outcomes[] | select(.scenario=="Baseline" and .summary=="Success")] | length' "$f")"
    if [ "$total" -eq 0 ]; then
        if [ "$rc" -eq 0 ]; then echo "none"; else echo "broken rc=${rc}, outcomes.json lists no mutant"; fi
    elif [ "$baseline" -eq 0 ]; then echo "broken rc=${rc}, the unmutated baseline did not pass"
    elif [ "$timeouts" -gt 0 ]; then echo "broken rc=${rc}, ${timeouts} mutant(s) timed out: inconclusive"
    elif [ "$rc" -eq 2 ] && [ "$missed" -eq 0 ]; then echo "broken rc=2 but no missed mutant recorded"
    elif [ "$rc" -eq 0 ] && [ "$missed" -gt 0 ]; then echo "broken rc=0 but ${missed} missed mutant(s) recorded"
    else echo "ok $total $missed"; fi
}

# mutation_score_of <exit code> <outcomes.json> — for release-check: prints
# "<score %> <caught> <total>", "n/a (no mutants in diff) 0 0", or
# "failed (<reason>)" and returns 1. Judged by mutants_outcome, as the gate is.
mutation_score_of() {
    local outcome caught total
    outcome="$(mutants_outcome "$1" "$2")"
    case "$outcome" in
        none) echo "n/a (no mutants in diff) 0 0" ;;
        ok\ *)
            read -r _ total _ <<<"$outcome"
            caught="$(jq '[.outcomes[] | select((.scenario|type=="object") and .scenario.Mutant and .summary=="CaughtMutant")] | length' "$2")"
            echo "$(awk -v c="$caught" -v t="$total" 'BEGIN{printf "%.1f", c/t*100}') $caught $total" ;;
        *) echo "failed (${outcome#broken })"; return 1 ;;
    esac
}
