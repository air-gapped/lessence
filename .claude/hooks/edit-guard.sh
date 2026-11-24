#!/usr/bin/env bash
# PreToolUse hook for Edit|Write|NotebookEdit (.claude/settings.json). The
# main session decides and writes briefs; workers edit src/ and tests/.
#
# Reads the hook's JSON on stdin. A call without `agent_id` (the main
# session; only subagent calls carry it) whose file_path resolves inside
# this repo under src/ or tests/ is refused. Everything else passes.
#
#   echo '{"tool_input":{"file_path":"src/x.rs"}}' | .claude/hooks/edit-guard.sh
set -euo pipefail

input=$(cat)
agent_id=$(printf '%s' "$input" | jq -r '.agent_id // empty')
file=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
if [ -n "$agent_id" ] || [ -z "$file" ]; then
    exit 0
fi

root=$(git rev-parse --show-toplevel)
case "$file" in
    /*) abs="$file" ;;
    *) abs="$root/$file" ;;
esac
abs=$(realpath -m -- "$abs")

case "$abs" in
    "$root"/src/* | "$root"/tests/*)
        jq -n --arg reason "edit-guard: the main session does not edit src/ or tests/. Write a brief with the decision and hand it to a worker (Agent tool); the main session runs make ci and make gate once over the round." \
            '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
        ;;
esac
exit 0
