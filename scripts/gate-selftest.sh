#!/usr/bin/env bash
# Checks that the gate's two acceptance measurements fail closed. Stubs
# stand in for the binary, the tokenizer and /usr/bin/time; nothing here
# builds or measures anything real, so it runs in a second.
#
#   ./scripts/gate-selftest.sh      — prints one line per check, exit 1 on any failure.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

ok() { echo "ok   - $1"; }
bad() {
    echo "FAIL - $1"
    fails=$((fails + 1))
}
check() { # check <name> <expected substring> <actual>
    if [[ "$3" == *"$2"* ]]; then ok "$1"; else
        bad "$1: expected to find '$2' in: $3"
    fi
}

# ── A stub lessence: one corpus in, a locator-bearing overview out ─────────
stub_bin="$WORK/lessence"
cat >"$stub_bin" <<'STUB'
#!/usr/bin/env bash
echo "report: /x/report.jsonl  file: complete  input: complete  run: r-1  size: 10 bytes  groups: 9 total, 4 selected, 3 printed, 6 omitted"
echo "previewed here: template"
echo "briefing" >&2
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$stub_bin"

corpus="$WORK/tiny.log"
echo "hello" >"$corpus"

size() { # size <baseline> [bless] -> the JSON
    python3 "$ROOT/scripts/gate-size.py" "$stub_bin" "$1" "$corpus" "${2:-}"
}
errors_of() { python3 -c 'import json,sys; print(" | ".join(json.load(sys.stdin)["errors"]))'; }
over_of() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["over"]))'; }

# 1. Missing tokenizer fails. A stub tiktoken earlier on PYTHONPATH than the
#    real one raises on import, which is what an uninstalled tiktoken does.
mkdir -p "$WORK/notiktoken"
echo 'raise ImportError("stub: no tiktoken")' >"$WORK/notiktoken/tiktoken.py"
out="$(PYTHONPATH="$WORK/notiktoken" size "$WORK/absent.json" | errors_of)"
check "missing tokenizer fails" "tokenizer unavailable" "$out"

# 2. Missing baseline fails, and says how to create one deliberately.
out="$(size "$WORK/absent.json" | errors_of)"
check "missing baseline fails" "GATE_BLESS_SIZE=1" "$out"

# Bless one, explicitly, to compare against below.
base="$WORK/baseline.json"
size "$base" bless >/dev/null
[ -s "$base" ] && ok "bless creates the baseline" || bad "bless creates the baseline"

# 3. A corpus absent from the baseline fails, naming it.
empty="$WORK/empty-corpora.json"
echo '{"corpora": {}}' >"$empty"
out="$(size "$empty" | errors_of)"
check "missing corpus fails" "corpus tiny is not in the baseline" "$out"

# 4. A baseline entry missing a field fails, naming corpus and field.
holed="$WORK/holed.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
del d["corpora"]["tiny"]["stderr_tokens"]
json.dump(d, open(sys.argv[2], "w"))
' "$base" "$holed"
out="$(size "$holed" | errors_of)"
check "missing field fails" "baseline tiny is missing field stderr_tokens" "$out"

# 5. A genuine growth fails, naming corpus and field. Shrink the baseline's
#    stdout_bytes far below what the stub prints.
grown="$WORK/grown.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
d["corpora"]["tiny"]["stdout_bytes"] = 10
json.dump(d, open(sys.argv[2], "w"))
' "$base" "$grown"
out="$(size "$grown" | over_of)"
check "growth fails, names the corpus" '"corpus": "tiny"' "$out"
check "growth fails, names the field" '"field": "stdout_bytes"' "$out"

# 5b. A baseline made with another tokenizer is not the pinned comparison.
retok="$WORK/retok.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
d["tokenizer"]["version"] = "0.0.0-other"
json.dump(d, open(sys.argv[2], "w"))
' "$base" "$retok"
out="$(size "$retok" | errors_of)"
check "changed tokenizer identity fails" "tokenizer identity differs from the baseline" "$out"

# 5c. A corpus whose bytes changed under the same name is not the baselined corpus.
redig="$WORK/redig.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
d["corpora"]["tiny"]["corpus_sha256"] = "0" * 64
json.dump(d, open(sys.argv[2], "w"))
' "$base" "$redig"
out="$(size "$redig" | errors_of)"
check "changed corpus digest fails" "corpus tiny changed since the baseline" "$out"

# 5d. A corpus in the baseline that was not measured is a missing inventory item.
out="$(python3 "$ROOT/scripts/gate-size.py" "$stub_bin" "$base" "" | errors_of)"
check "unmeasured baselined corpus fails" "corpus tiny is in the baseline but was not measured" "$out"

# 6. A non-zero exit from the measured binary is an error, never a number.
out="$(STUB_EXIT=3 size "$base" | errors_of)"
check "a failed run is an error" "exited 3" "$out"

# 7. stdout over 16 KiB is an error even when the baseline agrees.
big="$WORK/lessence-big"
cat >"$big" <<'STUB'
#!/usr/bin/env bash
printf 'report: x  groups: 1 total, 1 selected, 1 printed, 0 omitted\n'
head -c 20000 /dev/zero | tr '\0' 'x'
STUB
chmod +x "$big"
out="$(python3 "$ROOT/scripts/gate-size.py" "$big" "$base" "$corpus" "" | errors_of)"
check "over-16-KiB stdout is an error" "over the 16384-byte bound" "$out"

# ── RSS: the same three failure branches, with a stubbed /usr/bin/time ─────
GATE_DIR="$WORK/gate"
mkdir -p "$GATE_DIR"
PERF_CORPUS="$corpus"
report_args() { :; }
export GATE_DIR PERF_CORPUS
# shellcheck source=scripts/gate-rss.sh
. "$ROOT/scripts/gate-rss.sh"

# A working stub: writes a time -v report to -o, runs the command.
time_ok="$WORK/time-ok"
cat >"$time_ok" <<'STUB'
#!/usr/bin/env bash
out="$3"; shift 3
printf '\tMaximum resident set size (kbytes): 4242\n' >"$out"
"$@"
STUB
chmod +x "$time_ok"

GATE_TIME="$time_ok"
kb="$(rss_kb good "$stub_bin" 2>/dev/null)"
[ "$kb" = "4242" ] && ok "a good measurement returns the number" || bad "a good measurement returns the number (got '$kb')"

# A binary that fails: no number, non-zero status, diagnostics kept.
if STUB_EXIT=4 rss_kb badrun "$stub_bin" >/dev/null 2>"$WORK/err"; then
    bad "a non-zero run fails the measurement"
else
    check "a non-zero run fails the measurement" "exited non-zero" "$(cat "$WORK/err")"
    [ -f "$GATE_DIR/rss-badrun.stderr" ] && ok "diagnostics are kept" || bad "diagnostics are kept"
fi

# time itself reporting no peak RSS: also a failure, not an empty pass.
time_mute="$WORK/time-mute"
cat >"$time_mute" <<'STUB'
#!/usr/bin/env bash
out="$3"; shift 3
: >"$out"
"$@"
STUB
chmod +x "$time_mute"
GATE_TIME="$time_mute"
if rss_kb mute "$stub_bin" >/dev/null 2>"$WORK/err"; then
    bad "a measurement without a number fails"
else
    check "a measurement without a number fails" "no numeric peak RSS" "$(cat "$WORK/err")"
fi

echo "--- $fails failure(s)"
[ "$fails" -eq 0 ]
