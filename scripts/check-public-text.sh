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
#   scripts/check-public-text.sh --outgoing [REMOTE]  every commit a push
#                                                  would send (pre-push hook stdin)
#
# What to do when it stops you: write the material in your private notes
# and commit only what the code now does, in neutral words ("mask values
# inside quoted strings"). The owner, and only the owner, can publish such
# text on purpose with OWNER_APPROVED_PUBLIC_SECURITY_TEXT=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The two lists are untracked, so a linked worktree does not have them: they
# are read from the main checkout, wherever this runs.
MAIN="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
LISTS=("$MAIN/.blocklist" "$MAIN/.private-names")

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
        case "$name" in
            *.proptest-regressions)
                complain "$name: a property-test failure file holds the failing input; move it out of the tree and keep it in the private notes"
                ;;
        esac
    done
}

# stdin: a unified diff. Prints "file<TAB>line" for each added line. A line
# is a file header only between "diff" and the first "@@" of that file, so an
# added line that starts with "++" is read as content.
added_lines() {
    awk '
        /^diff / { in_hunk = 0; file = ""; next }
        /^@@/ { in_hunk = 1; next }
        !in_hunk && /^\+\+\+ / { file = substr($0, 5); sub(/^b\//, "", file); next }
        in_hunk && /^\+/ { print file "\t" substr($0, 2) }
    '
}

# stdin: a unified diff. Reports weakness words on added lines of prose files.
check_added_prose() {
    added_lines | PROSE="$PROSE_PATHS" awk -F'\t' '$1 ~ ENVIRON["PROSE"]' | while IFS=$'\t' read -r file line; do
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
    local patterns
    patterns=$(cat "${LISTS[@]}" 2>/dev/null | grep -vE '^(#|$)' || true)
    if [ -z "$patterns" ]; then
        cat >/dev/null
        echo 0
        return
    fi
    added_lines | cut -f2- | grep -cFf <(printf '%s\n' "$patterns") || true
}

# $1: the message; $2: "strip" drops "#" lines, as git's default cleanup does
# for a message still being edited. A committed message is read whole.
check_message() {
    local text="$1"
    if [ "${2:-}" = strip ]; then
        text=$(printf '%s\n' "$text" | grep -v '^#' || true)
    fi
    local word
    word=$(printf '%s\n' "$text" | grep -oiE "$WEAKNESS_WORDS" | head -1 || true)
    if [ -n "$word" ]; then
        complain "the commit message contains \"$word\"; describe the fix, not the hole"
    fi
    local list
    for list in "${LISTS[@]}"; do
        [ -f "$list" ] || continue
        while IFS= read -r pattern || [ -n "$pattern" ]; do
            case "$pattern" in ""|\#*) continue ;; esac
            if printf '%s\n' "$text" | grep -qF "$pattern"; then
                complain "the commit message contains a string from $(basename "$list")"
            fi
        done < "$list"
    done
}

# Every staged file's full content, read from the index, against .blocklist.
check_staged_blobs() {
    local list="$MAIN/.blocklist" path pattern
    [ -f "$list" ] || return 0
    while IFS= read -r -d '' path; do
        [ "$path" = ".blocklist" ] && continue
        while IFS= read -r pattern || [ -n "$pattern" ]; do
            case "$pattern" in ""|\#*) continue ;; esac
            if git cat-file blob ":$path" 2>/dev/null | grep -qF -- "$pattern"; then
                complain "blocklisted pattern '$pattern' found in staged $path"
            fi
        done < "$list"
    done < <(git diff --cached --name-only -z --diff-filter=ACMRT)
}

report_private_names() {
    if [ "$1" -gt 0 ]; then
        complain "$1 added line(s) hold a string from .blocklist or .private-names; take the private name or location out"
    fi
}

case "${1:-}" in
    --staged)
        check_names < <(git diff --cached --name-only --diff-filter=ACMRT)
        added=$(git diff --cached -U0 --diff-filter=ACMRT | check_added_prose)
        complaints=$((complaints + added))
        report_private_names "$(git diff --cached -U0 --diff-filter=ACMRT | check_added_private_names)"
        check_staged_blobs
        ;;
    --message)
        check_message "$(cat "$2")" strip
        ;;
    --outgoing)
        # stdin: the lines git gives a pre-push hook; $2: the destination
        # remote's name. A new ref is read back to what that remote's
        # tracking refs already hold; with no named remote, all of it.
        remote="${2:-}"
        zero=0000000000000000000000000000000000000000
        while read -r _ local_sha _ remote_sha; do
            [ "$local_sha" = "$zero" ] && continue
            if [ "$remote_sha" = "$zero" ]; then
                if [ -n "$remote" ] && git remote | grep -qxF -- "$remote"; then
                    revs=$(git rev-list "$local_sha" --not --remotes="$remote/*")
                else
                    revs=$(git rev-list "$local_sha")
                fi
            else
                revs=$(git rev-list "$remote_sha..$local_sha")
            fi
            for rev in $revs; do
                if ! "$0" --commit "$rev"; then
                    complain "commit $(git log -1 --format='%h %s' "$rev" | cut -c1-70) must not be pushed"
                fi
            done
        done
        ;;
    --commit)
        # A merge is read against each parent.
        check_names < <(git show --format= --diff-merges=separate --name-only --diff-filter=ACMRT "$2")
        added=$(git show --format= --diff-merges=separate -U0 --diff-filter=ACMRT "$2" | check_added_prose)
        complaints=$((complaints + added))
        report_private_names "$(git show --format= --diff-merges=separate -U0 --diff-filter=ACMRT "$2" | check_added_private_names)"
        check_message "$(git show -s --format=%B "$2")"
        ;;
    *)
        echo "usage: $0 --staged | --message FILE | --commit REV | --outgoing [REMOTE]" >&2
        exit 2
        ;;
esac

if [ "$complaints" -gt 0 ]; then
    echo "check-public-text: $complaints thing(s) that must not be published. See the top of scripts/check-public-text.sh." >&2
    exit 1
fi
