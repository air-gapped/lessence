#!/usr/bin/env bash
# Peak-RSS measurement for scripts/gate.sh. Defines functions only; sourced
# by the gate and by scripts/gate-selftest.sh. Running it does nothing.
#
# Fails closed: a measured run that exits non-zero, or a /usr/bin/time report
# without a numeric "Maximum resident set size", is a measurement failure and
# never a number the gate can pass on. The failed run's stderr is kept under
# target/gate for diagnosis.

# rss_kb <label> <binary> [extra args...] — prints peak RSS in KiB, or
# returns 1 having explained itself on stderr.
#
# Requires: GATE_DIR, PERF_CORPUS, and a report_args function, all from the
# caller. LC_ALL=C because "Maximum resident set size" is a translated string.
rss_kb() {
    local label="$1" bin="$2"
    shift 2
    local out diag kb
    out="$(mktemp)"
    diag="$GATE_DIR/rss-${label}.stderr"
    local extra=()
    mapfile -t extra < <(report_args "$bin")
    if ! LC_ALL=C "$GATE_TIME" -v -o "$out" \
        "$bin" --threads 1 -q "${extra[@]}" "$@" "$PERF_CORPUS" >/dev/null 2>"$diag"; then
        echo "rss: the ${label} run exited non-zero; its stderr is in $diag" >&2
        rm -f "$out"
        return 1
    fi
    kb="$(LC_ALL=C awk '/Maximum resident set size/ { print $NF }' "$out")"
    if ! [[ "$kb" =~ ^[0-9]+$ ]]; then
        echo "rss: no numeric peak RSS in the ${label} measurement; kept $diag" >&2
        cp "$out" "$GATE_DIR/rss-${label}.time" 2>/dev/null || true
        rm -f "$out"
        return 1
    fi
    rm -f "$out" "$diag"
    printf '%s\n' "$kb"
}
