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
#   scripts/check-mutants-pins.sh    exit 1 and one line per dead entry
#
# To re-pin: `cargo mutants --list --no-config | grep '<function name>'`,
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
cargo mutants --list --no-config >"$listing"
if [ ! -s "$listing" ]; then
    echo "check-mutants-pins: cargo mutants --list printed nothing" >&2
    exit 2
fi

python3 - "$listing" <<'PY'
import re
import sys
import tomllib

mutants = open(sys.argv[1], encoding="utf-8").read().splitlines()
with open(".cargo/mutants.toml", "rb") as f:
    entries = tomllib.load(f).get("exclude_re", [])

dead = [e for e in entries if not any(re.search(e, m) for m in mutants)]
for e in dead:
    print(f"dead exclude_re entry, matches no mutant: {e}")
if dead:
    print(
        f"{len(dead)} of {len(entries)} entries in .cargo/mutants.toml match nothing. "
        "Re-pin each to the mutant its comment describes "
        "(cargo mutants --list --no-config | grep '<function>'), "
        "or delete it if the code it excused is gone."
    )
    sys.exit(1)
print(f"mutants pins: {len(entries)} entries, each matches a mutant")
PY
