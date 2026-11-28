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
    out=$(printf '%s' "$3" | .claude/hooks/edit-guard.sh)
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
    out=$(printf '%s' "$3" | .claude/hooks/stop-guard.sh)
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
stop_case "quoted announcement" allow "$(stop_json $'I kept ending turns on "next I will fix it" and you asked for a check.\n\nNothing needed from you.')"
stop_case "backticked announcement" allow "$(stop_json $'The guard matches `I will now run` in a final message.\n\nNothing needed from you.')"
stop_case "quote then real announcement" block "$(stop_json 'You said "stop". Next I go on with the types.')"
stop_case "finished" allow "$(stop_json $'All four are fixed and pushed.\n\nNothing needed from you.')"
stop_case "action line" allow "$(stop_json $'The tag is ready.\n\n**Action for you:** say go and the release starts.')"
stop_case "no closing line" block "$(stop_json "All four are fixed and pushed.")"
stop_case "open work, nothing needed" block "$(stop_json $'Item 8 is done. Items 1 and 3 are still open.\n\nNothing needed from you.')"
stop_case "open work with a reason" allow "$(stop_json $'Two beads are still open.\nNot doing now: you asked only for the list.\n\nNothing needed from you.')"
stop_case "offer, nothing needed" block "$(stop_json $'I would delete those seven; say the word and I will do it.\n\nNothing needed from you.')"
stop_case "stop_hook_active" allow "$(stop_json "$announce" '{"stop_hook_active":true}')"
stop_case "background task" allow "$(stop_json "$announce" '{"background_tasks":[{"id":"x"}]}')"

# pgrep is stubbed to report a build in progress, so a command the guard
# wrongly takes for a build is refused whatever runs on this machine.
busy_dir=$(mktemp -d)
printf '#!/bin/sh\necho "4242 cargo build"\n' > "$busy_dir/pgrep"; chmod +x "$busy_dir/pgrep"
build_case() { # name expect(deny|allow) command
    local out
    out=$(jq -nc --arg c "$3" '{tool_input: {command: $c}}' | PATH="$busy_dir:$PATH" .claude/hooks/build-guard.sh)
    cases=$((cases + 1))
    if [ "$2" = deny ] && ! printf '%s' "$out" | grep -q 'hides its progress'; then
        echo "hooks selftest: FAIL build-guard should refuse: $1" >&2; exit 1
    fi
    if [ "$2" = allow ] && [ -n "$out" ]; then
        echo "hooks selftest: FAIL build-guard should allow: $1" >&2; exit 1
    fi
}
build_case "release-check through tail" deny "make release-check 2>&1 | tail -60"
build_case "mutants script through head" deny "scripts/mutants.sh -f src/x.rs | head -5"
build_case "a listing through tail" allow "ls scripts | tail -3"
build_case "long run with an env prefix through tail" deny "RELEASE_BASE=v1 make release-check 2>&1 | tail -5"
build_case "long run named in text, then head elsewhere" allow $'echo "run make release-check at handoff"\nls scripts | head -3'

# Every build entry point meets the resource checks. The memory floor is
# set out of reach and pgrep stubbed to find nothing, so the refusal is the
# memory one whatever runs on this machine.
probe_dir=$(mktemp -d)
printf '#!/bin/sh\nexit 1\n' > "$probe_dir/pgrep"; chmod +x "$probe_dir/pgrep"
heavy_case() { # name expect(deny|allow) command
    local out
    out=$(jq -nc --arg c "$3" '{tool_input: {command: $c}}' | PATH="$probe_dir:$PATH" LESSENCE_BUILD_MIN_AVAILABLE_GB=1000000 .claude/hooks/build-guard.sh)
    cases=$((cases + 1))
    if [ "$2" = deny ] && ! printf '%s' "$out" | grep -q 'of memory is available'; then
        echo "hooks selftest: FAIL build-guard should check resources for: $1" >&2; exit 1
    fi
    if [ "$2" = allow ] && [ -n "$out" ]; then
        echo "hooks selftest: FAIL build-guard should allow: $1" >&2; exit 1
    fi
}
heavy_case "make build" deny "make build"
heavy_case "make mutants" deny "make mutants"
heavy_case "make mutants-full" deny "make mutants-full"
heavy_case "mutants script" deny "scripts/mutants.sh -f src/x.rs"
heavy_case "dot-slash gate script" deny "./scripts/gate.sh"
heavy_case "dot-slash release-check script" deny "./scripts/release-check.sh"
heavy_case "cargo build" deny "cargo build --release"
heavy_case "a listing" allow "ls scripts"
heavy_case "after cd and &&" deny "cd /x && make gate"
heavy_case "with an env prefix" deny "GATE_BLESS_SIZE=1 make gate"
heavy_case "in a subshell" deny "(make ci)"
heavy_case "after a newline" deny $'git status\ncargo test --lib'
heavy_case "a script named in a quoted description" allow 'br create "gate fix" --description "run scripts/gate.sh, then make gate again"'
heavy_case "scripts named as arguments" allow "ocr scan scripts/gate.sh scripts/release-check.sh"
heavy_case "a build named in single quotes" allow "git commit -m 'make ci passes'"
rm -rf "$probe_dir" "$busy_dir"

review_guard_case() { # name expect(deny|allow) json
    local out
    out=$(printf '%s' "$3" | .claude/hooks/build-guard.sh)
    cases=$((cases + 1))
    if [ "$2" = deny ] && ! printf '%s' "$out" | grep -q 'does not record its own review'; then
        echo "hooks selftest: FAIL build-guard should refuse: $1" >&2; exit 1
    fi
    if [ "$2" = allow ] && [ -n "$out" ]; then
        echo "hooks selftest: FAIL build-guard should allow: $1" >&2; exit 1
    fi
}
review_guard_case "main session records a review" deny '{"tool_input":{"command":"scripts/record-review.sh pass ok"}}'
review_guard_case "main session mentions the script" allow '{"tool_input":{"command":"git commit -m \"the reviewer runs `scripts/record-review.sh` itself\""}}'
review_guard_case "reviewer records a review" allow '{"agent_id":"a1","agent_type":"fold-reviewer","tool_input":{"command":"scripts/record-review.sh pass ok"}}'

review_dir=$(mktemp -d)
review_case() { # name expect(pass|fail) gate-json review-json-or-empty
    printf '%s' "$3" > "$review_dir/gate.json"
    [ ! -e "$review_dir/review.json" ] || mv "$review_dir/review.json" "$review_dir/previous.json"
    [ -z "$4" ] || printf '%s' "$4" > "$review_dir/review.json"
    cases=$((cases + 1))
    if scripts/check-fold-review.sh "$review_dir/gate.json" "$review_dir/review.json" >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [ "$got" != "$2" ]; then
        echo "hooks selftest: FAIL fold review should $2: $1" >&2; exit 1
    fi
}
quiet='{"staged_diff_sha256":"aa","golden":[{"corpus":"k","added":[],"removed":[],"recounted":[]}]}'
moved='{"staged_diff_sha256":"aa","golden":[{"corpus":"k","added":["x"],"removed":[],"recounted":[]}]}'
review_case "no golden changed" pass "$quiet" ""
review_case "golden changed, no review" fail "$moved" ""
review_case "golden changed, review passes" pass "$moved" '{"staged_diff_sha256":"aa","verdict":"pass","summary":"k ok"}'
review_case "review for another change" fail "$moved" '{"staged_diff_sha256":"bb","verdict":"pass","summary":"k ok"}'
review_case "reviewer found a defect" fail "$moved" '{"staged_diff_sha256":"aa","verdict":"fail","summary":"k: a folds with b"}'

# check-public-text.sh in a scratch repository with its own lists.
# PUBLIC_TEXT_SCRIPT and GITLEAKS_CONFIG select the files under test.
public_text_script="${PUBLIC_TEXT_SCRIPT:-$ROOT/scripts/check-public-text.sh}"
pt_dir=$(mktemp -d)
pt_git() { git -C "$pt_dir" -c core.hooksPath=/dev/null -c commit.gpgsign=false -c user.name=t -c user.email=t@example.invalid "$@"; }
pt_git init -q -b main
mkdir -p "$pt_dir/scripts"
cp "$public_text_script" "$pt_dir/scripts/check-public-text.sh"
printf 'placeholder-name-q7\n' > "$pt_dir/.private-names"
printf 'listed-host-q7\n' > "$pt_dir/.blocklist"
printf '/.private-names\n/.blocklist\n/scripts/\n' > "$pt_dir/.git/info/exclude"
echo base > "$pt_dir/base.txt"; pt_git add base.txt; pt_git commit -qm base
public_text_case() { # name expect(pass|fail) args...
    local name="$1" expect="$2" got; shift 2
    cases=$((cases + 1))
    if (cd "$pt_dir" && scripts/check-public-text.sh "$@" < "${pt_stdin:-/dev/null}") >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [ "$got" != "$expect" ]; then
        echo "hooks selftest: FAIL check-public-text should $expect: $name" >&2; exit 1
    fi
}

printf '++ placeholder-name-q7\n' > "$pt_dir/plus.rs"; pt_git add plus.rs
public_text_case "an added line that starts with ++ is read" fail --staged
pt_git rm -q --cached plus.rs; rm "$pt_dir/plus.rs"

ln -s base.txt "$pt_dir/link.md"; pt_git add link.md; pt_git commit -qm link
rm "$pt_dir/link.md"; printf 'placeholder-name-q7\n' > "$pt_dir/link.md"; pt_git add link.md
public_text_case "a symlink replaced by a file is read" fail --staged
pt_git reset -q --hard

printf 'listed-host-q7\n' > "$pt_dir/old.txt"; pt_git add old.txt
OWNER_APPROVED_PUBLIC_SECURITY_TEXT=1 pt_git commit -qm old
echo more >> "$pt_dir/old.txt"; pt_git add old.txt
public_text_case "a staged file's whole content is read against .blocklist" fail --staged
pt_git reset -q --hard; pt_git rm -q old.txt; pt_git commit -qm drop

{ printf 'listed-host-q7\n'; head -c 300000 /dev/zero | tr '\0' 'x'; printf '\n'; } > "$pt_dir/big.txt"
pt_git add big.txt; OWNER_APPROVED_PUBLIC_SECURITY_TEXT=1 pt_git commit -qm big
echo more >> "$pt_dir/big.txt"; pt_git add big.txt
public_text_case "a match at the start of a large staged file is found" fail --staged
pt_git reset -q --hard; pt_git rm -q big.txt; pt_git commit -qm dropbig

printf 'placeholder-name-q7\n' > "$pt_dir/locked.txt"; pt_git add locked.txt
chmod 000 "$pt_dir/.private-names"
public_text_case "an unreadable list refuses" fail --staged
chmod 644 "$pt_dir/.private-names"
pt_git rm -q --cached locked.txt; rm "$pt_dir/locked.txt"

printf 'a note\n# placeholder-name-q7\n' > "$pt_dir/msg"
public_text_case "a # line of a message is read" fail --message "$pt_dir/msg"
printf 'a note\n# ------------------------ >8 ------------------------\n+placeholder-name-q7\n' > "$pt_dir/msg2"
public_text_case "what follows the scissors line is not read" pass --message "$pt_dir/msg2"
pt_git commit -q --allow-empty --cleanup=verbatim -F "$pt_dir/msg"
public_text_case "a # line of a committed message is read" fail --commit HEAD
pt_git reset -q --hard HEAD~1

pt_git checkout -qb side
printf 'placeholder-name-q7\n' > "$pt_dir/side.txt"; pt_git add side.txt; pt_git commit -qm side
pt_git checkout -q main
echo other > "$pt_dir/main.txt"; pt_git add main.txt; pt_git commit -qm main
pt_git merge -q --no-ff -m merge side
public_text_case "a merge is read against each parent" fail --commit HEAD
pt_git reset -q --hard HEAD~1; pt_git branch -qD side

printf 'placeholder-name-q7\n' > "$pt_dir/far.txt"; pt_git add far.txt; pt_git commit -qm far
pt_git remote add public /dev/null; pt_git remote add mirror /dev/null
pt_git update-ref refs/remotes/mirror/main HEAD
printf 'refs/heads/main %s refs/heads/main %040d\n' "$(pt_git rev-parse HEAD)" 0 > "$pt_dir/push"
pt_stdin="$pt_dir/push" public_text_case "a new ref is read back to the destination's own refs" fail --outgoing public
pt_git update-ref refs/remotes/public/main HEAD
pt_stdin="$pt_dir/push" public_text_case "history the destination already holds is not read again" pass --outgoing public
pt_git remote set-url --push public /nonexistent-push-target
pt_stdin="$pt_dir/push" public_text_case "a remote that pushes elsewhere than it fetches is read whole" fail --outgoing public
pt_git remote set-url --push --delete public /nonexistent-push-target
rm -rf "$pt_dir"

if command -v gitleaks >/dev/null 2>&1; then
    gl_dir=$(mktemp -d)
    mkdir -p "$gl_dir/docs"
    gl_value=$(printf '%s' Zx8Kq2Lm N4pR7sT1 vW3yB6cD 9fG0hJ5k)
    printf 'api_%s = "%s"\n' key "$gl_value" > "$gl_dir/docs/a.md"
    cases=$((cases + 1))
    gl_config="${GITLEAKS_CONFIG:-$ROOT/.gitleaks.toml}"
    if (cd "$gl_dir" && gitleaks dir --no-banner -c "$gl_config" .) >/dev/null 2>&1; then
        echo "hooks selftest: FAIL gitleaks should report a non-UUID key in docs/" >&2; exit 1
    fi
    rm -rf "$gl_dir"
fi

echo "hooks selftest: $cases cases pass"
