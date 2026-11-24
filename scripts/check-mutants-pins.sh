#!/usr/bin/env bash
# Every `exclude_re` entry in .cargo/mutants.toml must match at least one
# mutant cargo-mutants generates from the tree as it is now.
#
# An entry that pins `file:line:col` matches nothing once the code above it
# moves. It then hides no mutant, the mutant it was written for shows up as
# MISSED at the next release check, and the proof in its comment is attached
# to nothing. This runs in `make ci`, so the entry is re-pinned in the
# commit that moves the code.
#
#   scripts/check-mutants-pins.sh           exit 1 and one line per dead entry
#   scripts/check-mutants-pins.sh --repin   first move the dead pins whose
#                                           line only shifted, then report
#   scripts/check-mutants-pins.sh --selftest  check the --repin placement
#                                           on made-up input; needs no
#                                           cargo-mutants
#
# --repin places a dead pin two ways, each printing its move. First through
# the change since the last commit: `git diff -U0 HEAD -- <file>` says where
# the pinned line of HEAD now sits (a line inside a changed hunk has no new
# place). The pin moves there when a mutant sits at that line with the same
# column and text, and the source line there reads exactly as the pinned
# line did in HEAD. Second, for pins the diff cannot place: the dead pins of
# one shape (same file, column, text and function) move when mutants of
# that shape sit on exactly as many lines as there are pins, and each new
# line reads the same as the pinned line did in the last commit.
#
# What --repin leaves: `cargo mutants --list --no-config | grep '<function>'`,
# pick the mutant the entry's comment describes, and write its location.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# The check itself; --selftest runs it before cargo-mutants is looked for.
pins_py="$(cat <<'PY'
import re
import subprocess
import sys
import tomllib

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PIN = re.compile(r"^(\^src/[^:]+:)(\d+)(:.*)$")


def hunks_of(diff):
    """(old start, old count, new start, new count) per `git diff -U0` hunk."""
    out = []
    for line in diff.splitlines():
        h = HUNK.match(line)
        if h:
            a, b, c, d = h.groups()
            out.append((int(a), 1 if b is None else int(b), int(c), 1 if d is None else int(d)))
    return out


def map_line(hunks, old):
    """Where line `old` of the last commit sits now, or None when a hunk
    changed it. A hunk of old count 0 inserts after its old start."""
    shift = 0
    for a, b, _, d in hunks:
        if b and a <= old < a + b:
            return None
        if (a + b - 1 if b else a) < old:
            shift += d - b
    return old + shift


def diff_place(e, hunks, was, now, mutants):
    """The entry `e` moved to where the diff puts its line, or None: the
    line was changed, no mutant of the same column and text sits there, or
    the source line there does not read as it did in the last commit."""
    pin = PIN.match(e)
    if not pin or was is None:
        return None
    old = int(pin.group(2))
    line = map_line(hunks, old)
    if line is None or line == old or old > len(was) or not 0 < line <= len(now):
        return None
    if was[old - 1] != now[line - 1]:
        return None
    new = f"{pin.group(1)}{line}{pin.group(3)}"
    return new if any(re.search(new, m) for m in mutants) else None


def selftest():
    diff = "\n".join([
        "diff --git a/src/x.rs b/src/x.rs",
        "@@ -0,0 +1,2 @@",      # two lines added at the top
        "+a", "+b",
        "@@ -5 +7 @@",          # line 5 edited
        "-e", "+E",
        "@@ -8,2 +9,0 @@",      # lines 8-9 removed
        "-h", "-i",
        "@@ -12,0 +12,3 @@",    # three lines added after line 12
        "+x", "+y", "+z",
    ])
    hunks = hunks_of(diff)
    assert hunks == [(0, 0, 1, 2), (5, 1, 7, 1), (8, 2, 9, 0), (12, 0, 12, 3)], hunks
    expect = {1: 3, 4: 6, 5: None, 6: 8, 7: 9, 8: None, 9: None, 10: 10, 12: 12, 13: 16}
    got = {old: map_line(hunks, old) for old in expect}
    assert got == expect, got
    assert map_line([], 7) == 7

    was = [f"line {i}" for i in range(1, 15)]
    now = ["a", "b"] + was[:4] + ["E"] + was[5:7] + was[9:12] + ["x", "y", "z"] + was[12:]
    # The made-up file agrees with the diff: every mapped line reads the same.
    assert all(now[got[o] - 1] == was[o - 1] for o in got if got[o]), now
    pin = r"^src/x\.rs:4:9: replace \+ with \* in f$"
    listing = ["src/x.rs:6:9: replace + with * in f", "src/x.rs:6:9: replace + with - in f"]
    assert diff_place(pin, hunks, was, now, listing) == r"^src/x\.rs:6:9: replace \+ with \* in f$"
    # A closure's pin has no function name; the same rule places it.
    closure = r"^src/x\.rs:13:29: replace && with \|\|$"
    assert diff_place(closure, hunks, was, now, ["src/x.rs:16:29: replace && with ||"]) \
        == r"^src/x\.rs:16:29: replace && with \|\|$"
    # Refused: another column, an edited line, a line whose text differs.
    assert diff_place(pin, hunks, was, now, ["src/x.rs:6:10: replace + with * in f"]) is None
    assert diff_place(r"^src/x\.rs:5:9: replace \+ with \* in f$", hunks, was, now,
                      ["src/x.rs:7:9: replace + with * in f"]) is None
    edited = list(now)
    edited[5] = "line 4 changed"
    assert diff_place(pin, hunks, was, edited, listing) is None
    assert diff_place(pin, hunks, None, now, listing) is None
    print("check-mutants-pins selftest: ok")


if sys.argv[1:] == ["--selftest"]:
    selftest()
    sys.exit(0)

text = open(sys.argv[1], encoding="utf-8").read()
mutants = re.sub(r"\x1b\[[0-9;]*m", "", text).splitlines()
if not any(re.match(r"^src/\S+:\d+:\d+: ", m) for m in mutants):
    print("check-mutants-pins: the listing has no `src/file:line:col: ` line; first line was:")
    print(repr(mutants[0]) if mutants else "(empty)")
    sys.exit(2)
with open(".cargo/mutants.toml", "rb") as f:
    entries = tomllib.load(f).get("exclude_re", [])

dead = [e for e in entries if not any(re.search(e, m) for m in mutants)]

# --repin: code above a pin moved and took the pin's line with it. The diff
# since the last commit places what it can; of the rest, where the entry
# with its line number left open matches mutants on as many lines as there
# are such pins, those lines are the new places. The file is rewritten and
# the rest are left for a reader.
if dead and "--repin" in sys.argv[2:]:
    text = open(".cargo/mutants.toml", encoding="utf-8").read()
    moved = 0

    def committed(path):
        shown = subprocess.run(
            ["git", "show", f"HEAD:{path}"], capture_output=True, text=True
        )
        return shown.stdout.splitlines() if shown.returncode == 0 else None

    def unescape(head):
        return re.sub(r"\\(.)", r"\1", head[1:-1])

    committed_toml = "\n".join(committed(".cargo/mutants.toml") or [])
    # A pin's line number refers to the last commit's file only when the
    # entry itself is unchanged since then.
    for e in dead:
        pin = PIN.match(e)
        if not pin or text.count(e) != 1 or e not in committed_toml:
            continue
        path = unescape(pin.group(1))
        diff = subprocess.run(
            ["git", "diff", "-U0", "HEAD", "--", path], capture_output=True, text=True
        ).stdout
        now = open(path, encoding="utf-8").read().splitlines()
        new = diff_place(e, hunks_of(diff), committed(path), now, mutants)
        if new:
            text = text.replace(e, new)
            print(f"re-pinned (diff): {e}\n               to: {new}")
            moved += 1
    dead = [e for e in dead if e in text]

    # Dead pins that differ only in their line number, by that shared shape.
    groups = {}
    for e in dead:
        pin = PIN.match(e)
        if pin and text.count(e) == 1:
            groups.setdefault((pin.group(1), pin.group(3)), []).append((int(pin.group(2)), e))
    for (head, tail), pins in groups.items():
        loose = head + r"(\d+)" + tail
        lines = sorted({int(m.group(1)) for m in (re.search(loose, x) for x in mutants) if m})
        # As many places as pins: code moved, order kept, so the first pin
        # goes to the first place. Any other count is for a reader.
        if len(lines) != len(pins):
            continue
        # A pin moves only when the source line it lands on reads the same
        # as the line it was written for, taken from the last commit. A line
        # that was edited, or a look-alike elsewhere in the function, is a
        # different mutant and its proof has to be read again.
        path = unescape(head)
        was = committed(path)
        now = open(path, encoding="utf-8").read().splitlines()
        pairs = list(zip(sorted(pins), lines))
        differs = [
            (old, line)
            for (old, e), line in pairs
            if e not in committed_toml
            or was is None
            or old > len(was)
            or was[old - 1].strip() != now[line - 1].strip()
        ]
        if differs:
            for old, line in differs:
                print(
                    f"not re-pinned: {path}:{old} in the last commit and "
                    f"{path}:{line} now are not the same source line; read "
                    "the entry's proof against the new code"
                )
            continue
        for (_, e), line in pairs:
            new = f"{head}{line}{tail}"
            text = text.replace(e, new)
            print(f"re-pinned (shape): {e}\n                to: {new}")
            moved += 1
    open(".cargo/mutants.toml", "w", encoding="utf-8").write(text)
    with open(".cargo/mutants.toml", "rb") as f:
        entries = tomllib.load(f).get("exclude_re", [])
    dead = [e for e in entries if not any(re.search(e, m) for m in mutants)]
    print(f"{moved} entries re-pinned, {len(dead)} left")
for e in dead:
    print(f"dead exclude_re entry, matches no mutant: {e}")
if dead:
    print(
        f"{len(dead)} of {len(entries)} entries in .cargo/mutants.toml match nothing. "
        "Run scripts/check-mutants-pins.sh --repin to move the ones whose "
        "line only shifted; re-pin the rest by hand to the mutant each "
        "comment describes (cargo mutants --list --no-config | grep "
        "'<function>'), or delete an entry whose code is gone."
    )
    sys.exit(1)
print(f"mutants pins: {len(entries)} entries, each matches a mutant")
PY
)"

if [ "${1:-}" = "--selftest" ]; then
    exec python3 -c "$pins_py" --selftest
fi

if ! cargo mutants --version >/dev/null 2>&1; then
    echo "check-mutants-pins: cargo-mutants is not installed (cargo install cargo-mutants)" >&2
    exit 2
fi

listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT
# CI sets CARGO_TERM_COLOR=always, which colours the listing; an escape
# sequence inside a line matches no entry.
cargo mutants --list --no-config --colors never >"$listing"
if [ ! -s "$listing" ]; then
    echo "check-mutants-pins: cargo mutants --list printed nothing" >&2
    exit 2
fi

python3 -c "$pins_py" "$listing" "$@"
