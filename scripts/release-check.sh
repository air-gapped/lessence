#!/usr/bin/env bash
# make release-check — see docs/verification.md "scripts/release-check.sh".
#
# GATE_BASE=<last tag> scripts/gate.sh + mutants --in-diff <tag>..HEAD
# + make ci + the slow test profile.
# No original corpus is read (gate.sh reads only examples/distilled/*.log).
# Writes target/gate/release.json, prints <=25 lines.
# RELEASE_CHECK_SKIP_MUTANTS=1 skips the mutants step (for testing this
# script itself — mutants alone can take 10+ minutes).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATE_DIR="target/gate"
mkdir -p "$GATE_DIR"

last_tag="$(git describe --tags --abbrev=0)"

echo "Running gate against $last_tag..." >&2
gate_status="PASS"
GATE_BASE="$last_tag" ./scripts/gate.sh || gate_status="FAIL"

# ── mutants --in-diff on <last-tag>..HEAD ───────────────────────────────

MUTANTS_MEM_MAX="${MUTANTS_MEM_MAX:-48G}"
MUTANTS_TIMEOUT_MULT="${MUTANTS_TIMEOUT_MULT:-3}"
MUTANTS_JOBS="${MUTANTS_JOBS:-8}"
# src/folder/ is a directory since the split; naming src/folder.rs excluded
# every folder change from the run (lessence-xr6).
MUTANTS_FILES=(-f 'src/folder/**/*.rs' -f src/normalize.rs -f 'src/patterns/**/*.rs')

mutation_score="skipped"
mutants_caught=0
mutants_total=0
if [ -n "${RELEASE_CHECK_SKIP_MUTANTS:-}" ]; then
    echo "RELEASE_CHECK_SKIP_MUTANTS=1 — skipping mutants" >&2
else
    diff_file="$(mktemp)"
    # Git pathspecs are not shell globs: '**/*.rs' matches nothing here, so
    # the directories are named literally (lessence-xr6, second finding).
    git diff "${last_tag}..HEAD" -- src/folder src/normalize.rs src/patterns > "$diff_file"
    echo "Running cargo mutants --in-diff ${last_tag}..HEAD..." >&2
    # A previous run's outcomes must not be read as this run's (lessence-xr6).
    rm -rf mutants.out
    # A user-scope unit caps memory the same way and needs no polkit
    # prompt, so the run also works from a non-interactive session.
    mutants_rc=0
    systemd-run --user --scope -p "MemoryMax=${MUTANTS_MEM_MAX}" nice -n 19 \
        env PROPTEST_CASES=32 PROPTEST_MAX_SHRINK_ITERS=100 \
        cargo mutants -j "$MUTANTS_JOBS" --timeout-multiplier "$MUTANTS_TIMEOUT_MULT" \
        "${MUTANTS_FILES[@]}" -C --lib --in-diff "$diff_file" \
        || mutants_rc=$?
    rm -f "$diff_file"
    outcomes="mutants.out/outcomes.json"
    if [ ! -f "$outcomes" ]; then
        # cargo mutants exits non-zero when mutants are missed, which is a
        # score, not a failure; no outcomes at all is a failure to run.
        mutation_score="failed (rc=${mutants_rc}, no outcomes written)"
        gate_status="FAIL"
    fi
    if [ -f "$outcomes" ]; then
        mutants_caught="$(jq '[.outcomes[] | select(.scenario.Mutant and .summary=="Caught")] | length' "$outcomes" 2>/dev/null || echo 0)"
        mutants_total="$(jq '[.outcomes[] | select(.scenario.Mutant)] | length' "$outcomes" 2>/dev/null || echo 0)"
        if [ "$mutants_total" -gt 0 ]; then
            mutation_score="$(awk -v c="$mutants_caught" -v t="$mutants_total" 'BEGIN{printf "%.1f", c/t*100}')"
        else
            mutation_score="n/a (no mutants in diff)"
        fi
    fi
fi

# ── make ci ──────────────────────────────────────────────────────────────

echo "Running make ci..." >&2
ci_status="pass"
if ! make -C "$ROOT" ci >/tmp/release-check-ci.$$ 2>&1; then
    ci_status="FAIL"
fi
ci_tail="$(tail -8 /tmp/release-check-ci.$$)"
rm -f /tmp/release-check-ci.$$

# ── slow tests: the wall-clock profile the default profile excludes ─────

echo "Running slow tests (cargo nextest run --release --profile slow)..." >&2
slow_status="pass"
if ! cargo nextest run --release --profile slow >/tmp/release-check-slow.$$ 2>&1; then
    slow_status="FAIL"
fi
slow_tail="$(tail -8 /tmp/release-check-slow.$$)"
rm -f /tmp/release-check-slow.$$

# ── Output ───────────────────────────────────────────────────────────────

echo ""
echo "release-check: $last_tag vs working tree"
echo "gate: $gate_status (see target/gate/gate.json)"
echo "mutants: ${mutants_caught}/${mutants_total} caught (${mutation_score}%)"
echo "make ci: $ci_status"
if [ "$ci_status" = "FAIL" ]; then
    echo "$ci_tail"
fi
echo "slow tests: $slow_status"
if [ "$slow_status" = "FAIL" ]; then
    echo "$slow_tail"
fi

# ── release.json ─────────────────────────────────────────────────────────

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$GATE_DIR/release.json" <<JSON
{
  "time": "${now}",
  "git_head": "$(git rev-parse HEAD)",
  "base_tag": "${last_tag}",
  "gate": "${gate_status}",
  "mutants": {"caught": ${mutants_caught}, "total": ${mutants_total}, "score_pct": "${mutation_score}"},
  "ci": "${ci_status}",
  "slow": "${slow_status}"
}
JSON

[ "$gate_status" != "FAIL" ] && [ "$ci_status" = "pass" ] && [ "$slow_status" = "pass" ]
