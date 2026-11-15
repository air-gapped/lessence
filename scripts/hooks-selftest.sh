#!/usr/bin/env bash
# Checks that the edit and stop guards deny and allow what they should.
# Part of `make ci`.
#
#   scripts/hooks-selftest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cases=0

edit_case() { # name expect(deny|allow) json
    local out
    out=$(printf '%s' "$3" | scripts/edit-guard.sh)
    cases=$((cases + 1))
    if [ "$2" = deny ] && ! printf '%s' "$out" | grep -q '"permissionDecision": *"deny"'; then
        echo "hooks selftest: FAIL edit-guard should deny: $1" >&2; exit 1
    fi
    if [ "$2" = allow ] && [ -n "$out" ]; then
        echo "hooks selftest: FAIL edit-guard should allow: $1" >&2; exit 1
    fi
}

stop_case() { # name expect(block|allow) json
    local out
    out=$(printf '%s' "$3" | scripts/stop-guard.sh)
    cases=$((cases + 1))
    if [ "$2" = block ] && ! printf '%s' "$out" | grep -q '"decision": *"block"'; then
        echo "hooks selftest: FAIL stop-guard should block: $1" >&2; exit 1
    fi
    if [ "$2" = allow ] && [ -n "$out" ]; then
        echo "hooks selftest: FAIL stop-guard should allow: $1" >&2; exit 1
    fi
}

edit_json() { jq -nc --arg f "$1" --arg a "${2:-}" '{tool_name: "Edit", tool_input: {file_path: $f}} + (if $a == "" then {} else {agent_id: $a, agent_type: "general-purpose"} end)'; }

for f in "$ROOT/src/x.rs" "$ROOT/tests/y.rs" src/x.rs tests/y.rs; do
    edit_case "main $f" deny "$(edit_json "$f")"
    edit_case "worker $f" allow "$(edit_json "$f" a1)"
done
edit_case "main README.md" allow "$(edit_json "$ROOT/README.md")"
edit_case "main scripts/a.sh" allow "$(edit_json scripts/a.sh)"
edit_case "main outside repo" allow "$(edit_json /tmp/src/x.rs)"

stop_json() { jq -nc --arg m "$1" --argjson extra "${2:-{\}}" '{last_assistant_message: $m} + $extra'; }

announce="Done with the first half, pushed as abc. Next I go on with the type changes."
stop_case "next I go on" block "$(stop_json "$announce")"
stop_case "I'll now run" block "$(stop_json "I'll now run the gate.")"
stop_case "finished" allow "$(stop_json "All four are fixed and pushed. Nothing is open.")"
stop_case "stop_hook_active" allow "$(stop_json "$announce" '{"stop_hook_active":true}')"
stop_case "background task" allow "$(stop_json "$announce" '{"background_tasks":[{"id":"x"}]}')"

echo "hooks selftest: $cases cases pass"
