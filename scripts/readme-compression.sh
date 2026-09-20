#!/usr/bin/env bash
# The README's "Real-World Compression" table, written by this script and nothing else.
#
#   ./scripts/readme-compression.sh v0.6.1          print the table for that release version
#   ./scripts/readme-compression.sh --write v0.6.1  replace the gen:compression region in README.md
#   (the version is an argument: Cargo.toml still carries the previous one until release-please bumps it)
#   ./scripts/readme-compression.sh --check  exit 1 unless the table was generated at a commit
#                                            whose src/ tree equals HEAD's (release-check runs this)
#
# Runs locally only: the originals under examples/originals/ are private and never in CI.
# Lines out = the full folded text (`--no-report -q`), the same view every earlier table counted.
set -u
export LC_ALL=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The repository whose HEAD stamps the numbers and whose src/ must be clean.
# Overridable so the self-test can exercise the guards below against a repo of
# its own: this one is dirty in src/ exactly when a gate run is warranted, and
# a self-test that reads it could only ever pass when the gate was not needed.
REPO="${LESSENCE_REPO:-$ROOT}"
README="${LESSENCE_README:-$ROOT/README.md}"
BIN="${LESSENCE_BIN:-$ROOT/target/release/lessence}"
O="${LESSENCE_ORIGINALS:-$ROOT/examples/originals}"
ROWS="Kubernetes kubelet|kubelet.log
ArgoCD server|argocd_server_production.log
PostgreSQL primary|harbor_postgres_primary.log
Cilium networking|cilium_full.log
Rancher|rancher_production.log
journalctl (7 days)|epyc_7days_journalctl.log"

if [ "${1:-}" = --check ]; then
    at="$(sed -n 's/^<!-- gen:compression:at \([0-9a-f]*\) -->$/\1/p' "$README")"
    if [ -z "$at" ]; then echo "README compression table carries no generating commit; run scripts/readme-compression.sh --write" >&2; exit 1; fi
    if ! git -C "$REPO" cat-file -e "$at^{commit}" 2>/dev/null; then echo "README compression table was generated at unknown commit $at" >&2; exit 1; fi
    if ! git -C "$REPO" diff --quiet "$at" HEAD -- src/ Cargo.toml; then
        echo "README compression table was generated at $at; src/ changed since. Run scripts/readme-compression.sh --write" >&2; exit 1
    fi
    echo "README compression table is current (generated at $at)"; exit 0
fi

set -o pipefail
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }
version="${2:-${1:-}}"
case "$version" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "usage: $0 [--write] vX.Y.Z   (the version this table is released as)" >&2; exit 1 ;;
esac
head_sha="$(git -C "$REPO" rev-parse --short=9 HEAD)"
# The numbers are stamped with HEAD, so the binary must be HEAD's: its --version
# carries the commit it was built from, and the tree it was built from must be
# clean where folding lives. A stale binary would label old output as this commit.
built_from="$("$BIN" --version | sed -n 's/^lessence [^ ]* (\([0-9a-f]*\)\(-dirty\)\{0,1\},.*$/\1/p')"
if [ "$built_from" != "$head_sha" ]; then
    echo "binary $BIN was built from ${built_from:-?}, HEAD is $head_sha: rebuild (cargo build --release) before measuring" >&2; exit 1
fi
if ! git -C "$REPO" diff --quiet HEAD -- src/ Cargo.toml; then
    echo "src/ or Cargo.toml has uncommitted changes: commit them, rebuild, then measure" >&2; exit 1
fi
table="| Log source | Lines in | Lines out | Reduction |
|-----------|--------:|---------:|----------:|"
while IFS='|' read -r name file; do
    [ -f "$O/$file" ] || { echo "missing original: $O/$file" >&2; exit 1; }
    in=$(wc -l < "$O/$file")
    errfile="$(mktemp)"
    if ! out=$("$BIN" --no-report -q "$O/$file" 2>"$errfile" | wc -l); then
        echo "lessence failed on $file (exit status of the run is not 0):" >&2
        head -c 600 "$errfile" >&2; echo >&2
        rm -f "$errfile"; exit 1
    fi
    rm -f "$errfile"
    if [ "$out" -eq 0 ]; then echo "lessence printed no lines for $file; refusing to record a 100% row" >&2; exit 1; fi
    # One decimal, but never a rounded-up 100%: 21 lines out of 60,849 is 99.97%, and
    # "100%" would say nothing was left, which is false. Such rows print two decimals.
    pct=$(awk -v i="$in" -v o="$out" 'BEGIN { r = 100 * (1 - o / i); if (r >= 99.95) printf "%.2f%%", r; else printf "%.1f%%", r }')
    table="$table
| $name | $(python3 -c "print(f'{$in:,}')") | $(python3 -c "print(f'{$out:,}')") | $pct |"
done <<< "$ROWS"
block="<!-- gen:compression:begin -->
<!-- gen:compression:at $head_sha -->
Measured on $version (commit $head_sha) on production logs that are not
distributable. Every distinct message is its own event, so these counts are
lower than a looser folder would give.

$table
<!-- gen:compression:end -->"

if [ "${1:-}" = --write ]; then
    python3 - "$README" "$block" <<'EOF'
import re, sys
path, block = sys.argv[1], sys.argv[2]
s = open(path).read()
new, n = re.subn(r"<!-- gen:compression:begin -->.*?<!-- gen:compression:end -->", lambda m: block, s, count=1, flags=re.S)
if n != 1:
    sys.exit("README.md has no gen:compression region")
open(path, "w").write(new)
EOF
    echo "README.md compression table written ($version at $head_sha)"
else
    printf '%s\n' "$block"
fi
