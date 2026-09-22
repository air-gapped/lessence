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

# The base is the last PUBLISHED release: what users actually run. A tag can
# exist without a published release (v0.6.0 did), and comparing against it
# hides what the upgrade costs. `gh` knows which releases are published;
# RELEASE_BASE overrides; without gh the newest tag is used and said so.
if [ -n "${RELEASE_BASE:-}" ]; then
    last_tag="$RELEASE_BASE"
elif published="$(gh release list --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName' 2>/dev/null)" && [ -n "$published" ]; then
    last_tag="$published"
else
    last_tag="$(git describe --tags --abbrev=0)"
    echo "WARNING: gh unavailable; comparing against the newest tag $last_tag, which may be unpublished" >&2
fi

echo "Running gate against $last_tag (last published release)..." >&2
gate_status="PASS"
# Vacuity is judged per commit by the pre-commit gate; against the tag it
# is only a count (see gate.sh, lessence-km2).
GATE_BASE="$last_tag" GATE_VACUOUS_INFORMATIONAL=1 ./scripts/gate.sh || gate_status="FAIL"

# ── mutants --in-diff on <last-tag>..HEAD ───────────────────────────────

# This machine is a workstation, not a build box: a browser, an editor and
# whatever else is open have to survive the run. Budget from what is FREE
# right now, not from a number somebody picked when the machine was idle —
# `MemoryMax=48G` on a 62 GiB box with 39 GiB already in use is not a cap,
# it is permission to take everything, and the kernel pays for it by
# evicting the desktop.
#
# RESERVE_GIB is what is left for everything that is not this run.
MUTANTS_RESERVE_GIB="${MUTANTS_RESERVE_GIB:-16}"
avail_gib="$(awk '/^MemAvailable:/ {printf "%d", $2/1048576}' /proc/meminfo)"
budget_gib=$(( avail_gib - MUTANTS_RESERVE_GIB ))
[ "$budget_gib" -lt 4 ] && budget_gib=4
MUTANTS_MEM_MAX="${MUTANTS_MEM_MAX:-${budget_gib}G}"
MUTANTS_TIMEOUT_MULT="${MUTANTS_TIMEOUT_MULT:-3}"
# Each worker is a full cargo build tree. Memory, not cores, is what runs
# out first, so derive the worker count from the budget and cap it by the
# cores actually available.
jobs_by_mem=$(( budget_gib / 4 ))
[ "$jobs_by_mem" -lt 1 ] && jobs_by_mem=1
cores="$(nproc)"
[ "$jobs_by_mem" -gt "$cores" ] && jobs_by_mem="$cores"
[ "$jobs_by_mem" -gt 8 ] && jobs_by_mem=8
MUTANTS_JOBS="${MUTANTS_JOBS:-$jobs_by_mem}"
echo "mutants budget: ${MUTANTS_MEM_MAX} of ${avail_gib}G available, ${MUTANTS_JOBS} jobs (reserve ${MUTANTS_RESERVE_GIB}G)" >&2
if [ "$MUTANTS_JOBS" -le 1 ]; then
    echo "  only ${avail_gib}G free, so this runs single-job and will be slow." >&2
    echo "  Close what you can, or lower the reserve deliberately:" >&2
    echo "    MUTANTS_RESERVE_GIB=8 make release-check" >&2
fi
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
    # cargo mutants exits 0 (all caught), 2 (missed) or 3 (timeouts) after
    # a complete run. 4 is the baseline failing before any mutant ran, 1, 5
    # and 6 are usage and diff errors, 70 is internal (mutants.rs/exit-codes);
    # none of those, nor a partial or malformed outcomes.json, may be read
    # as a score (lessence-xr6).
    case "$mutants_rc" in
        0|2|3) mutants_complete=1 ;;
        *) mutants_complete=0 ;;
    esac
    if [ "$mutants_complete" -eq 0 ] || [ ! -f "$outcomes" ] \
        || ! jq -e '.outcomes | type == "array"' "$outcomes" >/dev/null 2>&1; then
        mutation_score="failed (rc=${mutants_rc}, no complete outcomes)"
        gate_status="FAIL"
    else
        mutants_caught="$(jq '[.outcomes[] | select((.scenario|type=="object") and .scenario.Mutant and .summary=="CaughtMutant")] | length' "$outcomes")"
        mutants_total="$(jq '[.outcomes[] | select((.scenario|type=="object") and .scenario.Mutant)] | length' "$outcomes")"
        if [ "$mutants_total" -gt 0 ]; then
            mutation_score="$(awk -v c="$mutants_caught" -v t="$mutants_total" 'BEGIN{printf "%.1f", c/t*100}')"
        else
            mutation_score="n/a (no mutants in diff)"
        fi
    fi
fi

# ── README compression table: generated at a commit with today's src/ ───

echo "Checking the README compression table..." >&2
readme_status="pass"
readme_msg="$("$ROOT/scripts/readme-compression.sh" --check 2>&1)" || readme_status="FAIL"

# ── agent skill re-verified since the last behaviour change ─────────────
#
# This ran as a GitHub check on release-please's PR branch. With
# release-please gone there is no PR to hang it on, and a check that only
# fires on a branch nobody creates is a check that never runs — so it moves
# here, onto the path that actually precedes a tag.
#
# `.claude/skills/lessence/references/sources.md` carries `verified-at: <sha>`.
# Every user-facing src/ commit after that sha is a behaviour change the
# agent-facing skill has not been re-read against.

echo "Checking the agent skill was re-verified..." >&2
skill_status="pass"
skill_msg="ok"
sources="$ROOT/.claude/skills/lessence/references/sources.md"
verified_sha="$(grep -oE '^verified-at: [0-9a-f]{40}' "$sources" 2>/dev/null | awk '{print $2}')"
if [ -z "${verified_sha:-}" ]; then
    skill_status="FAIL"; skill_msg="sources.md has no 'verified-at: <sha>' line"
elif ! git -C "$ROOT" merge-base --is-ancestor "$verified_sha" HEAD 2>/dev/null; then
    skill_status="FAIL"; skill_msg="verified-at $verified_sha is not an ancestor of HEAD"
else
    unverified="$(git -C "$ROOT" log "$verified_sha"..HEAD --extended-regexp \
        --grep='^(feat|fix|perf)(\(.*\))?!?:' --format='%h %s' -- src/)"
    if [ -n "$unverified" ]; then
        skill_status="FAIL"
        skill_msg="not re-verified since: $(echo "$unverified" | tr '\n' ';' | cut -c1-160)"
    else
        skill_msg="verified-at ${verified_sha:0:9} covers every user-facing src/ commit"
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
echo "README compression table: $readme_status ($readme_msg)"
echo "agent skill: $skill_status ($skill_msg)"

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
  "slow": "${slow_status}",
  "readme_compression": "${readme_status}"
}
JSON

[ "$gate_status" != "FAIL" ] && [ "$ci_status" = "pass" ] && [ "$slow_status" = "pass" ] && [ "$readme_status" = "pass" ]
