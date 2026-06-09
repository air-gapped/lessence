#!/usr/bin/env bash
# Release-surface check: verify that the documentation surfaces shipping with
# a release (README, agent skill) match the actual binary behavior.
# Run BEFORE merging the release PR — crates.io freezes the README at the tag.
#
# Usage: ./scripts/release-surface-check.sh
# Exit 0 = all surfaces consistent, exit 1 = drift found.
set -u
cd "$(dirname "$0")/.."
BIN=./target/release/lessence
fail=0
err() { echo "FAIL: $*"; fail=1; }
ok() { echo "  ok: $*"; }

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

echo "== README test count vs reality =="
actual_tests=$(cargo nextest list 2>/dev/null | grep -c '::')
readme_tests=$(grep -oE '# [0-9,]+ tests' README.md | grep -oE '[0-9,]+' | tr -d ',')
if [ "${readme_tests:-0}" -eq "$actual_tests" ]; then
  ok "README says $readme_tests tests, nextest lists $actual_tests"
else
  err "README says '${readme_tests:-none}' tests, nextest lists $actual_tests — update README.md"
fi

if [ -f examples/kubelet.log ]; then
  echo "== README kubelet compression row vs reality =="
  actual_lines=$($BIN -q examples/kubelet.log | wc -l)
  readme_lines=$(grep 'Kubernetes kubelet' README.md | awk -F'|' '{gsub(/[ ,]/,"",$4); print $4}')
  if [ "${readme_lines:-0}" -eq "$actual_lines" ]; then
    ok "kubelet row: $actual_lines output lines"
  else
    err "README kubelet row says ${readme_lines:-?} lines, binary produces $actual_lines — re-measure README table"
  fi
fi

echo "== README/skill jq recipes still parse real output =="
sample=$(printf '2024-01-01T10:00:00Z ERROR conn refused from 10.0.0.1\n%.0s' 1 2 3 4 | $BIN --format json 2>/dev/null)
echo "$sample" | jq -e 'select(.type=="summary") | .input_lines' >/dev/null 2>&1 \
  && ok "summary record parses" || err "--format json summary record changed shape"

echo "== Skill sources.md staleness =="
newest=$(grep -oE '\| [0-9]{4}-[0-9]{2}-[0-9]{2} \|' .claude/skills/lessence/references/sources.md | tr -d '| ' | sort | tail -1)
if [ -n "$newest" ]; then
  age_days=$(( ( $(date +%s) - $(date -d "$newest" +%s) ) / 86400 ))
  if [ "$age_days" -le 30 ]; then
    ok "newest sources.md stamp $newest (${age_days}d old)"
  else
    err "newest sources.md stamp $newest is ${age_days}d old — re-verify the skill against the binary"
  fi
else
  err "no Last-verified stamps found in skill sources.md"
fi

echo "== Impossible rollup counts in README examples =="
# Per-token distinct counts cap at 64; ×N with N>64 (without '+') cannot occur.
if grep -oE '[a-z_0-9]+×[0-9]+' README.md | awk -F'×' '$2 > 64 {print; exit 1}' >/dev/null; then
  ok "no marker shows a distinct count above the 64 cap"
else
  err "README example shows token×N with N > 64 — impossible since the rollup cap; paste a real run"
fi

[ "$fail" -eq 0 ] && echo "ALL SURFACES CONSISTENT" || echo "SURFACE DRIFT — fix before merging the release PR"
exit "$fail"
