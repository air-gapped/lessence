#!/usr/bin/env bash
# Shows that every event family of a previous distilled copy is still present
# in the regenerated examples/distilled/<name>.log (bead lessence-1s7y, part a).
#
# usage: scripts/check-distill-families.sh [OLD_DIR]   (default examples/distilled.prev)
#
# A family is a --explain group's normalized template. An old template is
# present when a new template has the same structure: the same whitespace
# sequence of placeholders, punctuation and word runs (words joined by . _ -),
# where <VARIES> on either side stands for one or more units of the other,
# and a run is equal or, when it holds invented words, has the same kept words
# and the same alphanumeric length. A word is invented when it does not occur
# in examples/originals/<name>.log (a kept literal always does); words under
# three letters count as invented, since inventions that short collide with
# real words by chance, and so do digit-only words. Only templates
# (scrubbed text) are printed, never a line of an original.
set -euo pipefail
cd "$(dirname "$0")/.."
OLD_DIR=${1:-examples/distilled.prev}
BIN=${LESSENCE_BIN:-target/release/lessence}
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 2; }
[ -d "$OLD_DIR" ] || { echo "no old dir $OLD_DIR" >&2; exit 2; }
exec python3 -I - "$OLD_DIR" "$BIN" <<'PY'
import json, re, subprocess, sys, pathlib
old_dir, binp = pathlib.Path(sys.argv[1]), sys.argv[2]
UNIT = re.compile(r'<[A-Z][A-Z0-9_]*>|[A-Za-z0-9]+(?:[._-]+[A-Za-z0-9]+)*|\s+|.')
WORD = re.compile(r'[A-Za-z0-9]+')
VAR = '<VARIES>'

def templates(path):
    out = subprocess.run([binp, '--explain', '--threads', '1', str(path)],
                         capture_output=True, text=True, check=True).stdout
    ts = []
    for line in out.splitlines():
        try: d = json.loads(line)
        except ValueError: continue
        if d.get('type') == 'group': ts.append(d['normalized'])
    return ts

def vocab(path):
    v = set()
    with open(path, 'rb') as f:
        for line in f:
            v.update(WORD.findall(line.decode('utf-8', 'replace')))
    return v

def units(t, voc):
    # A run of words joined by . _ - is one unit. With an original to look
    # at, it is reduced to its kept words (length >= 3 and in the original:
    # shorter inventions collide with real words by chance) plus the total
    # length of its alphanumerics (digit-only words never count as kept:
    # an invented number turns up in a large original by chance), because two anonymizer versions split an
    # invented dotted name into different pieces of the same total length.
    out = []
    for u in UNIT.findall(t.strip()):
        if u[0].isspace(): out.append(' '); continue
        if WORD.match(u) and voc is not None:
            ws = WORD.findall(u)
            if any(w not in voc for w in ws):
                kept = tuple(w for w in ws if len(w) >= 3 and w in voc
                             and not w.isdigit())
                u = ('RUN', kept, sum(map(len, ws)))
        out.append(u)
    return out

def subseq(small, big):
    it = iter(big)
    return all(any(u == b for b in it) for u in small)

def matches(o, n):
    vo, vn = VAR in o, VAR in n
    if not vo and not vn:
        return o == n
    # cheap necessary conditions before the alignment
    if o[0] != n[0] and VAR not in (o[0], n[0]): return False
    if o[-1] != n[-1] and VAR not in (o[-1], n[-1]): return False
    if vn and not vo and not (len(o) >= len(n) and subseq([u for u in n if u != VAR], o)): return False
    if vo and not vn and not (len(n) >= len(o) and subseq([u for u in o if u != VAR], n)): return False
    I, J = len(o), len(n)
    M = [[False] * (J + 1) for _ in range(I + 1)]
    M[I][J] = True
    S = [[False] * (J + 2) for _ in range(I + 2)]  # S[i][j] = any M[k][j] for k >= i
    S[I][J] = True
    for i in range(I, -1, -1):
        rowsuf = False
        R = [False] * (J + 2)  # R[j] = any M[i+1][k] for k >= j
        if i < I:
            for k in range(J, -1, -1):
                rowsuf = rowsuf or M[i + 1][k]; R[k] = rowsuf
        for j in range(J - 1 if i == I else J, -1, -1):
            if i == I or j == J:
                v = (i == I and j == J)
            elif o[i] == VAR: v = R[j + 1]
            elif n[j] == VAR: v = S[i + 1][j + 1]
            else: v = o[i] == n[j] and M[i + 1][j + 1]
            M[i][j] = v
            S[i][j] = v or S[i + 1][j]
    return M[0][0]

total = miss_total = 0; failed = []
for old in sorted(old_dir.glob('*.log')):
    name = old.stem; new = pathlib.Path('examples/distilled') / old.name
    orig = pathlib.Path('examples/originals') / old.name
    if not new.exists():
        print(f'{name} - - MISSING-NEW-COPY'); failed.append((name, ['(no regenerated copy)'])); continue
    voc = vocab(orig) if orig.exists() else None
    ot, nt = templates(old), templates(new)
    nset = set(nt)
    nu = [units(t, voc) for t in dict.fromkeys(nt)]
    fams = list(dict.fromkeys(ot))
    missing = [t for t in fams if t not in nset
               and not any(matches(units(t, voc), n) for n in nu)]
    note = '' if voc is not None else ' (no original: exact words only)'
    print(f'{name} {len(fams)} {len(fams)-len(missing)} {len(missing)}{note}')
    total += len(fams); miss_total += len(missing)
    if missing: failed.append((name, missing))
print(f'TOTAL {total} {total-miss_total} {miss_total}')
for name, ms in failed:
    print(f'\n== {name}: missing')
    for m in ms: print('  ' + m)
sys.exit(1 if failed else 0)
PY
