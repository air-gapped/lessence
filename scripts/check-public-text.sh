#!/usr/bin/env bash
# Everything committed here is published. This refuses the three things
# that must stay private, before they are committed:
#
#   1. a security working document, by file name;
#   2. prose that describes a weakness: added lines in Markdown, the issue
#      export and commit messages are read for the words below;
#   3. a string from the local, untracked `.blocklist` (private host names)
#      in a commit message; the pre-commit hook already reads staged files
#      against that list. And a string from the local, untracked
#      `.private-names` (where private notes live) on any added line or in
#      a commit message.
#
#   scripts/check-public-text.sh --staged          what `git commit` would publish
#   scripts/check-public-text.sh --message FILE    a commit message
#   scripts/check-public-text.sh --commit REV      one existing commit
#
# What to do when it stops you: write the material in your private notes
# and commit only what the code now does, in neutral words ("mask values
# inside quoted strings"). The owner, and only the owner, can publish such
# text on purpose with OWNER_APPROVED_PUBLIC_SECURITY_TEXT=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "${OWNER_APPROVED_PUBLIC_SECURITY_TEXT:-}" = "1" ]; then
    exit 0
fi

DOCUMENT_NAMES='(^|/)(THREAT[_-]?MODEL|VULN[_-]FINDINGS|TRIAGE)[^/]*$|(^|/)PATCHES/|pentest|audit[_-]report|security[_-]audit|sanitize[_-]audit|crash[_-]input|(^|/)poc[-_./]'
PROSE_PATHS='\.md$|^\.beads/issues\.jsonl$|\.txt$|\.html$'
WEAKNESS_WORDS='vulnerab|exploit|attack surface|threat model|proof[- ]of[- ]concept|\bpoc\b|cve-[0-9]|unfixed|unpatched|not yet fixed|crafted input|malicious input|can be bypassed|bypass(es|ed|ing)? the (mask|sanitiz|redact|scrub)|leaks? (the|a|an) (secret|credential|password|token|key)'

complaints=0
complain() {
    echo "check-public-text: $1" >&2
    complaints=$((complaints + 1))
}

check_names() {
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if printf '%s\n' "$name" | grep -qiE "$DOCUMENT_NAMES"; then
            complain "$name is a security working document by name; it stays out of the repo"
        fi
    done
}

# stdin: a unified diff. Reports weakness words on added lines of prose files.
check_added_prose() {
    PROSE="$PROSE_PATHS" awk '
        /^\+\+\+ / { file = substr($2, 3); in_prose = (file ~ ENVIRON["PROSE"]); next }
        /^\+/ && in_prose { print file "\t" substr($0, 2) }
    ' | while IFS=$'\t' read -r file line; do
        word=$(printf '%s\n' "$line" | grep -oiE "$WEAKNESS_WORDS" | head -1 || true)
        if [ -n "$word" ]; then
            printf '%s\t%s\n' "$file" "$word"
        fi
    done | sort -u | while IFS=$'\t' read -r file word; do
        echo "check-public-text: $file adds prose containing \"$word\"; describe what the code now does, and keep the weakness in private notes" >&2
        echo x
    done | wc -l
}

# stdin: a unified diff. Counts added lines, in any file, that hold a
# string from .private-names.
check_added_private_names() {
    [ -f .private-names ] || { echo 0; return; }
    grep -E '^\+' | grep -vE '^\+\+\+ ' | grep -cFf <(grep -vE '^(#|$)' .private-names) || true
}

check_message() {
    local text="$1"
    local word
    word=$(printf '%s\n' "$text" | grep -v '^#' | grep -oiE "$WEAKNESS_WORDS" | head -1 || true)
    if [ -n "$word" ]; then
        complain "the commit message contains \"$word\"; describe the fix, not the hole"
    fi
    local list
    for list in .blocklist .private-names; do
        [ -f "$list" ] || continue
        while IFS= read -r pattern || [ -n "$pattern" ]; do
            case "$pattern" in ""|\#*) continue ;; esac
            if printf '%s\n' "$text" | grep -v '^#' | grep -qF "$pattern"; then
                complain "the commit message contains a string from $list"
            fi
        done < "$list"
    done
}

report_private_names() {
    if [ "$1" -gt 0 ]; then
        complain "$1 added line(s) name a place from .private-names; say \"private notes\" and leave the location out"
    fi
}

case "${1:-}" in
    --staged)
        check_names < <(git diff --cached --name-only --diff-filter=ACMR)
        added=$(git diff --cached -U0 --diff-filter=ACMR | check_added_prose)
        complaints=$((complaints + added))
        report_private_names "$(git diff --cached -U0 --diff-filter=ACMR | check_added_private_names)"
        ;;
    --message)
        check_message "$(cat "$2")"
        ;;
    --commit)
        check_names < <(git show --format= --name-only --diff-filter=ACMR "$2")
        added=$(git show --format= -U0 --diff-filter=ACMR "$2" | check_added_prose)
        complaints=$((complaints + added))
        report_private_names "$(git show --format= -U0 --diff-filter=ACMR "$2" | check_added_private_names)"
        check_message "$(git show -s --format=%B "$2")"
        ;;
    *)
        echo "usage: $0 --staged | --message FILE | --commit REV" >&2
        exit 2
        ;;
esac

if [ "$complaints" -gt 0 ]; then
    echo "check-public-text: $complaints thing(s) that must not be published. See the top of scripts/check-public-text.sh." >&2
    exit 1
fi
