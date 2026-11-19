#!/usr/bin/env bash
# Stop hook (.claude/settings.json). A turn that ends by announcing the next
# step ("Next I go on with ...") has stopped before doing it.
#
# Reads the hook's JSON on stdin. Passes when already continuing because of
# a stop hook, or when background tasks are running (waiting is a legitimate
# stop). Otherwise the last 400 characters of the final message are read,
# and the stop is blocked if they announce work instead of doing it. Text
# inside quotes or backticks is quoted speech, not an announcement, and is
# left out.
#
#   echo '{"last_assistant_message":"Next I go on with the types."}' | scripts/stop-guard.sh
set -euo pipefail

input=$(cat)
if [ "$(printf '%s' "$input" | jq -r '.stop_hook_active // false')" = "true" ]; then
    exit 0
fi
if [ "$(printf '%s' "$input" | jq -r '(.background_tasks // []) | length')" -gt 0 ]; then
    exit 0
fi

tail_text=$(printf '%s' "$input" | jq -r '(.last_assistant_message // "") | .[-400:]' \
    | sed -E 's/"[^"]*"//g; s/`[^`]*`//g; s/“[^”]*”//g')

announce='\bnext,? I\b|\bI('"'"'ll| will) (now|next|then)\b|\bI take (it|that|this|those|these) next\b|\bI('"'"'m| am) (now )?(going to|starting|about to)\b|\bnext I (go|continue|take|run|do|start|fix|add)\b|\bI (then |now )?(continue|go on|proceed) with\b|\bI report (when|once)\b|\bthen I (run|commit|fix|hand)\b'
if printf '%s' "$tail_text" | grep -qiE "$announce"; then
    jq -n --arg reason "stop-guard: your last message announces a next step and then stops. Do that step now. If you are in fact finished or blocked, end with what is done and what blocks, with no promise of further work." \
        '{decision: "block", reason: $reason}'
fi
exit 0
