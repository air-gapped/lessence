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
#   scripts/check-mutants-pins.sh --repin   first move the dead pins of one
#                                           shape (same file, column, text
#                                           and function) when mutants of
#                                           that shape sit on exactly as
#                                           many lines as there are pins
#
# What --repin leaves: `cargo mutants --list --no-config | grep '<function>'`,
# pick the mutant the entry's comment describes, and write its location.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

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

python3 - "$listing" "$@" <<'PY'
import re
import sys
import tomllib

text = open(sys.argv[1], encoding="utf-8").read()
mutants = re.sub(r"\x1b\[[0-9;]*m", "", text).splitlines()
if not any(re.match(r"^src/\S+:\d+:\d+: ", m) for m in mutants):
    print("check-mutants-pins: the listing has no `src/file:line:col: ` line; first line was:")
    print(repr(mutants[0]) if mutants else "(empty)")
    sys.exit(2)
with open(".cargo/mutants.toml", "rb") as f:
    entries = tomllib.load(f).get("exclude_re", [])

dead = [e for e in entries if not any(re.search(e, m) for m in mutants)]

# --repin: code above a pin moved and took the pin's line with it. Where the
# entry with its line number left open matches mutants on exactly one line,
# that line is the pin's new place; the file is rewritten and the rest are
# left for a reader.
if dead and "--repin" in sys.argv[2:]:
    text = open(".cargo/mutants.toml", encoding="utf-8").read()
    moved = 0
    # Dead pins that differ only in their line number, by that shared shape.
    groups = {}
    for e in dead:
        pin = re.match(r"^(\^src/[^:]+:)(\d+)(:.*)$", e)
        if pin and text.count(e) == 1:
            groups.setdefault((pin.group(1), pin.group(3)), []).append((int(pin.group(2)), e))
    for (head, tail), pins in groups.items():
        loose = head + r"(\d+)" + tail
        lines = sorted({int(m.group(1)) for m in (re.search(loose, x) for x in mutants) if m})
        # As many places as pins: code moved, order kept, so the first pin
        # goes to the first place. Any other count is for a reader.
        if len(lines) != len(pins):
            continue
        for (_, e), line in zip(sorted(pins), lines):
            new = f"{head}{line}{tail}"
            text = text.replace(e, new)
            print(f"re-pinned: {e}\n        to: {new}")
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
