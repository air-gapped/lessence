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
# A final message also ends on one of two lines, so the owner sees at once
# whether anything is his: "**Action for you:** ..." or "Nothing needed from
# you." The second is refused when the same message lists open work or
# offers a choice, unless it says why with a "Not doing now:" line.
#
#   echo '{"last_assistant_message":"Next I go on with the types."}' | .claude/hooks/stop-guard.sh
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
    exit 0
fi

block() {
    jq -n --arg reason "stop-guard: $1" '{decision: "block", reason: $reason}'
    exit 0
}

message=$(printf '%s' "$input" | jq -r '.last_assistant_message // ""')
[ -n "$message" ] || exit 0
last_line=$(printf '%s\n' "$message" | sed -E 's/[[:space:]]+$//' | grep -v '^$' | tail -1 | sed -E 's/^\**//; s/\**$//')
unquoted=$(printf '%s' "$message" | sed -E 's/"[^"]*"//g; s/`[^`]*`//g; s/“[^”]*”//g')

case "$last_line" in
    "Action for you:"*) exit 0 ;;
    "Nothing needed from you."|"Nothing needed from you") ;;
    *) block "end the message with one of two lines: '**Action for you:** <what the owner must do>' or 'Nothing needed from you.'" ;;
esac

if printf '%s' "$unquoted" | grep -qiE '^\**Not doing now:'; then
    exit 0
fi
open_work='\b(still|remains?|are|is|stay|stays) (still |also )?open\b|\bnot (yet )?(done|built|started)\b|\bleft to do\b'
offer='\bsay the word\b|\blet me know if\b|\bshall I\b|\bdo you want me to\b|\byours? to (judge|decide)\b|\byour call\b|\bup to you\b|\bif you want,? I\b'
if printf '%s' "$unquoted" | grep -qiE "$open_work"; then
    block "the message says nothing is needed from the owner and also lists open work. Do that work now. If it is deliberately left, add a line starting 'Not doing now:' with the reason."
fi
if printf '%s' "$unquoted" | grep -qiE "$offer"; then
    block "the message offers the owner a choice and ends 'Nothing needed from you.' Decide it yourself and act, or end with '**Action for you:**' naming the one thing only the owner can decide."
fi
exit 0
