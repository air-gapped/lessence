#!/usr/bin/env bash
# PreToolUse hook for Bash (.claude/settings.json). One build or test run at
# a time on this machine, and none when memory is short: a release build
# here is fat LTO, and several agents each starting one took the machine out
# of memory on 2026-11-15.
#
# Reads the hook's JSON on stdin. A command that builds or tests is refused
# while another cargo, rustc or nextest process is running, or while less
# than MIN_AVAILABLE_GB of memory is available. A release-check or mutants
# run piped through tail or head is refused too: it would show nothing for
# its whole length, and so is scripts/record-review.sh from the main
# session: a review is recorded by the agent that did it. Everything else
# passes.
#
#   echo '{"tool_input":{"command":"cargo build"}}' | .claude/hooks/build-guard.sh
set -euo pipefail

MIN_AVAILABLE_GB="${LESSENCE_BUILD_MIN_AVAILABLE_GB:-10}"

input=$(cat)
command=$(printf '%s' "$input" | jq -r '.tool_input.command // empty')
# What the command runs: quoted strings are text (a commit message, a bead
# description), not commands, so the build check reads the command with them
# removed.
executed=$(printf '%s' "$input" | jq -r '.tool_input.command // empty
    | gsub("\u0027[^\u0027]*\u0027"; "") | gsub("\"([^\"\\\\]|\\\\.)*\""; "")')

if printf '%s' "$command" | grep -qE '(^|[;&|(])[[:space:]]*(bash[[:space:]]+)?(\./)?scripts/record-review\.sh' && [ -z "$(printf '%s' "$input" | jq -r '.agent_id // empty')" ]; then
    jq -n --arg reason "build-guard: the main session does not record its own review. Spawn the fold-reviewer agent; it reads the golden diff and records the verdict." \
        '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
    exit 0
fi

long_run='(^|[;&|(])[[:space:]]*([A-Za-z_]+=[^[:space:]]+[[:space:]]+)*(make[[:space:]]+(release-check|mutants|mutants-full)|(\./)?scripts/(release-check|mutants)\.sh)([^;&]|>&)*\|[[:space:]]*(tail|head)\b'
if printf '%s\n' "$command" | grep -qE "$long_run"; then
    jq -n --arg reason "build-guard: this run takes many minutes and tail or head hides its progress lines until the end. Run it without them, in the background; release-check also writes target/gate/release-check.log as it goes." \
        '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
    exit 0
fi
# A build counts only in command position: at the start of a line or after
# ; & | (, past any VAR=value prefixes and a time, nice or env wrapper. A
# script path given as an argument (ocr scan scripts/gate.sh) is not a run.
heavy='(^|[;&|(])[[:space:]]*([A-Za-z_]+=[^[:space:]]*[[:space:]]+)*((time|nice|env)[[:space:]]+)*(cargo[[:space:]]+(build|test|nextest|clippy|doc|run|bench|mutants|install|check)|make[[:space:]]+(ci|gate|release-check|install|test|clippy|doc|distill|build|mutants|mutants-full)|(\./)?scripts/(gate|release-check|mutants)\.sh)'
if ! printf '%s
' "$executed" | grep -qE "$heavy"; then
    exit 0
fi

refuse() {
    jq -n --arg reason "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
    exit 0
}

running=$(pgrep -x -a 'cargo|rustc|cargo-nextest|cargo-mutants' 2>/dev/null | grep -v 'cargo fmt' | head -1 || true)
if [ -n "$running" ]; then
    refuse "build-guard: another build or test run is in progress (${running:0:80}). One at a time on this machine. Do not retry in a loop: carry on with edits, or if you are a worker, finish your edits and report; the main session runs the build and tests once."
fi

available_gb=$(awk '/^MemAvailable:/ {printf "%d", $2 / 1048576}' /proc/meminfo)
if [ "$available_gb" -lt "$MIN_AVAILABLE_GB" ]; then
    refuse "build-guard: only ${available_gb} GB of memory is available (need ${MIN_AVAILABLE_GB}). Not starting a build. Tell the user; do not retry."
fi
