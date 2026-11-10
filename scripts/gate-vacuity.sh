#!/usr/bin/env bash
# New-case vacuity classification for scripts/gate.sh. Defines functions
# only; sourced by the gate and by scripts/gate-selftest.sh. Running it does
# nothing.
#
# vacuity_outcome <cargo test exit code> <captured output file>
#
# Reads what `cargo test --test integration -- --exact
# integration::test_fold_regressions::known_fold_regressions` printed for a
# fixture holding one new ##CASE, run against the baseline binary. Prints
# `passes` or `fails` and returns 0 only when the output shows that test
# reaching a result: `... ok` with exit 0, or `... FAILED` with the case
# check's own "N of M fold regressions came back" message. Anything else — a
# compile failure, a filter that matched nothing, a panic before the case was
# checked (an unreadable fixture, a binary that would not spawn) — prints
# nothing and returns 1: the case was never judged, so it is neither vacuous
# nor proven.
vacuity_outcome() {
    local rc="$1" out="$2"
    local line="test integration::test_fold_regressions::known_fold_regressions ..."
    if [ "$rc" -eq 0 ] && grep -qF "$line ok" "$out"; then
        echo passes
    elif [ "$rc" -ne 0 ] && grep -qF "$line FAILED" "$out" &&
        grep -qE '^[0-9]+ of [0-9]+ fold regressions came back' "$out"; then
        echo fails
    else
        return 1
    fi
}
