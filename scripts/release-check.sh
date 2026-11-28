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
# An earlier report must never be read as this run's verdict, whatever
# makes this run stop early; the new one appears only when complete.
rm -f "$GATE_DIR/release.json"

# Mutants select from the commits up to HEAD while the gate, builds and
# tests read the working tree, so the two agree only when every input of
# the verdict is committed: what builds the binary (the embedded skill
# included), what tests it, and the scripts and Makefile that judge it.
RELEASE_INPUTS=(src Cargo.toml Cargo.lock build.rs .claude/skills/lessence tests .config .cargo scripts Makefile)
if [ -n "$(git status --porcelain -- "${RELEASE_INPUTS[@]}")" ]; then
    echo "release-check: ${RELEASE_INPUTS[*]} has uncommitted changes; commit them first" >&2
    exit 1
fi

# Scratch files live in a private directory removed on every exit.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
trap 'exit 130' INT TERM
exec > >(tee "$GATE_DIR/release-check.log") 2>&1

# The base is the last PUBLISHED release: what users actually run. A tag can
# exist without a published release (v0.6.0 did), and comparing against it
# hides what the upgrade costs. `gh` knows which releases are published;
# RELEASE_BASE overrides; without gh the newest tag is used and said so.
# An empty list from a working gh is not an outage: there is no published
# release, and a local tag would silently stand in for one.
if [ -n "${RELEASE_BASE:-}" ]; then
    last_tag="$RELEASE_BASE"
elif published="$(gh release list --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName' 2>/dev/null)"; then
    if [ -z "$published" ]; then
        echo "release-check: no published release to compare against; set RELEASE_BASE=<ref>" >&2
        exit 1
    fi
    last_tag="$published"
elif last_tag="$(git describe --tags --abbrev=0 2>/dev/null)"; then
    echo "WARNING: gh unavailable; comparing against the newest tag $last_tag, which may be unpublished" >&2
else
    echo "release-check: gh unavailable and no tag is reachable from HEAD; set RELEASE_BASE=<ref>" >&2
    exit 1
fi
# One resolved commit feeds both the gate and the mutant selection;
# last_tag stays the label people read.
if ! base_commit="$(git rev-parse --verify --quiet --end-of-options "${last_tag}^{commit}")"; then
    echo "release-check: base '$last_tag' is not a commit" >&2
    exit 1
fi

echo "Running gate against $last_tag (last published release)..." >&2
gate_status="PASS"
# Vacuity is judged per commit by the pre-commit gate; against the tag it
# is only a count (see gate.sh, lessence-km2).
GATE_BASE="$base_commit" GATE_VACUOUS_INFORMATIONAL=1 ./scripts/gate.sh || gate_status="FAIL"

# shellcheck source=scripts/gate-measure.sh
. "$ROOT/scripts/gate-measure.sh"

# ── mutants --in-diff on <last-tag>..HEAD ───────────────────────────────

# src/folder/ is a directory since the split; naming src/folder.rs excluded
# every folder change from the run (lessence-xr6).
MUTANTS_FILES=(-f 'src/folder/**/*.rs' -f src/normalize.rs -f 'src/patterns/**/*.rs')

mutation_score="skipped"
mutants_caught=0
mutants_total=0
if [ -n "${RELEASE_CHECK_SKIP_MUTANTS:-}" ]; then
    echo "RELEASE_CHECK_SKIP_MUTANTS=1 — skipping mutants" >&2
else
    diff_file="$SCRATCH/mutants.diff"
    # Git pathspecs are not shell globs: '**/*.rs' matches nothing here, so
    # the directories are named literally (lessence-xr6, second finding).
    git diff "${base_commit}..HEAD" -- src/folder src/normalize.rs src/patterns > "$diff_file"
    echo "Running cargo mutants --in-diff ${last_tag}..HEAD..." >&2
    # A previous run's outcomes must not be read as this run's (lessence-xr6).
    rm -rf mutants.out
    # scripts/mutants.sh sizes the run to the memory free right now.
    mutants_rc=0
    scripts/mutants.sh "${MUTANTS_FILES[@]}" -C --lib --in-diff "$diff_file" \
        || mutants_rc=$?
    rm -f "$diff_file"
    # One judge for the gate and this check (scripts/gate-measure.sh): an
    # exit other than 0 or 2, a timeout, an empty or malformed outcomes.json,
    # a failed baseline or counts that disagree with the exit code are a
    # failed mutation step, never a score (lessence-xr6, lessence-65ct).
    if score_out="$(mutation_score_of "$mutants_rc" mutants.out/outcomes.json)"; then
        case "$score_out" in
            n/a*) mutation_score="n/a (no mutants in diff)" ;;
            *) read -r mutation_score mutants_caught mutants_total <<<"$score_out" ;;
        esac
    else
        mutation_score="$score_out"
        gate_status="FAIL"
    fi
fi

# ── README compression table: generated at a commit with today's src/ ───

echo "Checking the README compression table..." >&2
readme_status="pass"
readme_msg="$("$ROOT/scripts/readme-compression.sh" --check 2>&1)" || readme_status="FAIL"

# ── the agent skill moved with every behaviour change ───────────────────
#
# `.claude/skills/lessence/references/sources.md` carries `verified-at: <sha>`,
# the commit up to which the skill was read against the build by hand. Every
# user-facing src/ commit after it must have updated the skill in the same
# commit or carry `Skill-Unchanged: <reason>`: the rule the commit-msg hook
# applies at commit time, checked again here over the whole range.

echo "Checking the agent skill moved with each behaviour change..." >&2
skill_status="pass"
skill_msg="ok"
sources="$ROOT/.claude/skills/lessence/references/sources.md"
verified_sha="$(grep -oE '^verified-at: [0-9a-f]{40}' "$sources" 2>/dev/null | awk '{print $2}' || true)"
if [ -z "${verified_sha:-}" ]; then
    skill_status="FAIL"; skill_msg="sources.md has no 'verified-at: <sha>' line"
elif ! git -C "$ROOT" merge-base --is-ancestor "$verified_sha" HEAD 2>/dev/null; then
    skill_status="FAIL"; skill_msg="verified-at $verified_sha is not an ancestor of HEAD"
else
    unverified=""
    while read -r sha; do
        [ -n "$sha" ] || continue
        if git -C "$ROOT" show --format= --name-only --no-renames "$sha" | grep -q '^\.claude/skills/lessence/'; then
            continue
        fi
        if git -C "$ROOT" log -1 --format=%B "$sha" | grep -qE '^Skill-Unchanged: .+'; then
            continue
        fi
        unverified+="$(git -C "$ROOT" log -1 --format='%h %s' "$sha");"
    done < <(git -C "$ROOT" log "$verified_sha"..HEAD --extended-regexp \
        --grep='^(feat|fix|perf)(\(.*\))?!?:' --format='%H' -- src/)
    if [ -n "$unverified" ]; then
        skill_status="FAIL"
        skill_msg="neither updates the skill nor says Skill-Unchanged: $(echo "$unverified" | cut -c1-160)"
    else
        skill_msg="every user-facing src/ commit since ${verified_sha:0:9} updates the skill or says why not"
    fi
fi

# ── make ci ──────────────────────────────────────────────────────────────

echo "Running make ci..." >&2
ci_status="pass"
if ! make -C "$ROOT" ci >"$SCRATCH/ci" 2>&1; then
    ci_status="FAIL"
fi
ci_tail="$(tail -8 "$SCRATCH/ci")"
rm -f "$SCRATCH/ci"

# ── every release target type-checks ────────────────────────────────────
#
# This machine builds one target. 0.8.0 called a Linux-only API and was
# found not to compile on macOS only after its crate had published.
# `cargo check --target` needs no foreign linker, so it catches that class
# here in about a minute a target. It cannot run another platform's tests:
# the dry run of release-build.yml does that, on the real runners.
# The shipped lib and binary only — dev-dependencies build C code that
# needs each platform's own compiler.

RELEASE_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc)
echo "Type-checking every release target..." >&2
targets_status="pass"
targets_msg=""
installed="$(rustup target list --installed)"
for t in "${RELEASE_TARGETS[@]}"; do
    if ! grep -qx "$t" <<<"$installed"; then
        targets_status="FAIL"
        targets_msg+="$t not installed (rustup target add $t); "
    elif ! cargo check --release --target "$t" >"$SCRATCH/target" 2>&1; then
        targets_status="FAIL"
        targets_msg+="$t: $(grep -m1 '^error' "$SCRATCH/target"); "
    fi
done
rm -f "$SCRATCH/target"

# ── slow tests: the wall-clock profile the default profile excludes ─────

echo "Running slow tests (cargo nextest run --release --profile slow)..." >&2
slow_status="pass"
if ! cargo nextest run --release --profile slow >"$SCRATCH/slow" 2>&1; then
    slow_status="FAIL"
fi
slow_tail="$(tail -8 "$SCRATCH/slow")"
rm -f "$SCRATCH/slow"

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
echo "release targets: $targets_status${targets_msg:+ ($targets_msg)}"

# ── release.json ─────────────────────────────────────────────────────────

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# jq escapes every string; the counters are numbers or the step failed.
case "$mutants_caught$mutants_total" in *[!0-9]*|'') mutants_caught=0; mutants_total=0; gate_status="FAIL" ;; esac
jq -n --arg time "$now" --arg head "$(git rev-parse HEAD)" --arg base "$last_tag" \
    --arg base_commit "$base_commit" --arg gate "$gate_status" \
    --argjson caught "$mutants_caught" --argjson total "$mutants_total" --arg score "$mutation_score" \
    --arg ci "$ci_status" --arg slow "$slow_status" --arg readme "$readme_status" \
    --arg skill "$skill_status" --arg targets "$targets_status" \
    '{time: $time, git_head: $head, base_tag: $base, base_commit: $base_commit, gate: $gate,
      mutants: {caught: $caught, total: $total, score_pct: $score},
      ci: $ci, slow: $slow, readme_compression: $readme, agent_skill: $skill,
      release_targets: $targets}' >"$GATE_DIR/release.json.tmp"
mv -f "$GATE_DIR/release.json.tmp" "$GATE_DIR/release.json"

[ "$gate_status" != "FAIL" ] && [ "$ci_status" = "pass" ] && [ "$slow_status" = "pass" ] \
    && [ "$readme_status" = "pass" ] && [ "$skill_status" = "pass" ] && [ "$targets_status" = "pass" ]
