#!/usr/bin/env bash
# Checks that the gate's two acceptance measurements fail closed. Stubs
# stand in for the binary, the tokenizer and /usr/bin/time; nothing here
# builds or measures anything real, so it runs in a second.
#
#   ./scripts/gate-selftest.sh      — prints one line per check, exit 1 on any failure.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

# The fixture repos below are the self-test's own: no Git setting the caller
# exported (a hook's GIT_DIR or GIT_INDEX_FILE, user hooks, signing) reaches
# them or the scripts they run.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars 2>/dev/null)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

WORK="$(mktemp -d)" && [ -d "$WORK" ] || { echo "gate-selftest: mktemp -d failed" >&2; exit 2; }
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

# ── New-case vacuity: only a result the test reported counts ──────────────
# shellcheck source=scripts/gate-vacuity.sh
. "$ROOT/scripts/gate-vacuity.sh"
vac="$WORK/vacuity.out"
t="test integration::test_fold_regressions::known_fold_regressions ..."
outcome() { vacuity_outcome "$1" "$vac" || echo "error"; }

printf 'running 1 test\n%s ok\n\ntest result: ok. 1 passed; 0 failed\n' "$t" >"$vac"
check "a case that passes on the baseline is vacuous" "passes" "$(outcome 0)"

printf 'running 1 test\n%s FAILED\n\nthread panicked at tests/x.rs:1:1:\n1 of 1 fold regressions came back:\n' "$t" >"$vac"
check "a case that fails on the baseline is proven" "fails" "$(outcome 101)"

printf 'error[E0425]: cannot find value x in this scope\nerror: could not compile lessence\n' >"$vac"
check "a compile failure is a gate error, not a failing case" "error" "$(outcome 101)"

printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 256 filtered out\n' >"$vac"
check "a filter that ran nothing is a gate error, not a passing case" "error" "$(outcome 0)"

printf 'running 1 test\n%s FAILED\n\nthread panicked at tests/x.rs:22:59:\nLESSENCE_FIXTURE=/x: No such file or directory\n' "$t" >"$vac"
check "a panic before the case check is a gate error" "error" "$(outcome 101)"

# ── README compression table: a failing, empty or stale binary never becomes evidence ─
rc_orig="$WORK/originals"; mkdir -p "$rc_orig"
for f in kubelet.log argocd_server_production.log harbor_postgres_primary.log cilium_full.log rancher_production.log epyc_7days_journalctl.log; do
    printf 'a\nb\nc\n' >"$rc_orig/$f"
done
readme_copy="$WORK/README.md"; cp "$ROOT/README.md" "$readme_copy"
before="$(sha256sum "$readme_copy")"
# A repo of the self-test's own, so these cases test the guards rather than
# the state of the checkout they run in.
rc_repo="$WORK/repo"; mkdir -p "$rc_repo/src"
git -C "$rc_repo" init -q
git -C "$rc_repo" config user.email selftest@example.com
git -C "$rc_repo" config user.name selftest
: >"$rc_repo/src/lib.rs"; : >"$rc_repo/Cargo.toml"
git -C "$rc_repo" add -A
git -C "$rc_repo" commit -qm "self-test fixture"
head_sha="$(git -C "$rc_repo" rev-parse --short=9 HEAD)"
check "the fixture repo holds its own commit" "$rc_repo/.git" "$(cd "$rc_repo" && git rev-parse --absolute-git-dir)"
rc_bin="$WORK/lessence-rc"
mk_rc_bin() { # mk_rc_bin <version sha> <body>
    printf '#!/usr/bin/env bash\n[ "$1" = --version ] && { echo "lessence 0.0.0 (%s, x86_64-unknown-linux-gnu)"; exit 0; }\n%s\n' "$1" "$2" >"$rc_bin"
    chmod +x "$rc_bin"
}
rc() { LESSENCE_BIN="$rc_bin" LESSENCE_ORIGINALS="$rc_orig" LESSENCE_README="$readme_copy" LESSENCE_REPO="$rc_repo" "$ROOT/scripts/readme-compression.sh" --write v9.9.9 2>"$WORK/rc-err" >/dev/null; echo $?; }

mk_rc_bin "$head_sha" 'echo "boom" >&2; exit 3'
check "a failing lessence run is not recorded" "1" "$(rc)"
check "the failure's stderr is shown" "boom" "$(cat "$WORK/rc-err")"

mk_rc_bin "$head_sha" 'exit 0'
check "a run that prints nothing is not recorded" "1" "$(rc)"
check "the empty run is named" "refusing to record a 100% row" "$(cat "$WORK/rc-err")"

mk_rc_bin "deadbeef1" 'echo x; echo y'
check "a binary built from another commit is refused" "1" "$(rc)"
check "the stale binary is named" "was built from deadbeef1" "$(cat "$WORK/rc-err")"
check "the README copy was never written" "$before" "$(sha256sum "$readme_copy")"

# ── The change hash: staging a file, or a dirty bead export, moves nothing ─
# The pre-commit hook stages .beads/issues.jsonl itself. A hash that saw
# that, or that told staged from unstaged, refused the commit the gate had
# just passed.
hash_repo="$WORK/hash-repo"
mkdir -p "$hash_repo/src" "$hash_repo/.beads"
(
    cd "$hash_repo" || exit 2
    git init -q .
    echo a >src/x.rs
    echo '{}' >.beads/issues.jsonl
    git add -A
    git -c user.name=t -c user.email=t@example.invalid commit -q -m init
) >/dev/null 2>&1
dhash() { (cd "$hash_repo" && "$ROOT/scripts/gate-diff-hash.sh"); }
clean_hash="$(dhash)"
echo b >"$hash_repo/src/x.rs"
gated_hash="$(dhash)"
if [ "$gated_hash" != "$clean_hash" ]; then ok "a source change moves the hash"; else
    bad "a source change left the hash where it was"
fi
git -C "$hash_repo" add src/x.rs
check "staging the change keeps the hash" "$gated_hash" "$(dhash)"
echo '{"id":1}' >"$hash_repo/.beads/issues.jsonl"
check "a dirty bead export keeps the hash" "$gated_hash" "$(dhash)"
git -C "$hash_repo" add .beads
check "the hook staging the bead export keeps the hash" "$gated_hash" "$(dhash)"
echo c >"$hash_repo/src/x.rs"
if [ "$(dhash)" != "$gated_hash" ]; then ok "an edit after the gate moves the hash"; else
    bad "an edit after the gate left the hash where it was"
fi

# ── README --write: an updater that cannot write is a failure, not a success ─
noregion="$WORK/README-noregion.md"; echo "# no generated region here" >"$noregion"
mk_rc_bin "$head_sha" 'echo x; echo y'
nr_rc=0
LESSENCE_BIN="$rc_bin" LESSENCE_ORIGINALS="$rc_orig" LESSENCE_README="$noregion" LESSENCE_REPO="$rc_repo" \
    "$ROOT/scripts/readme-compression.sh" --write v9.9.9 >"$WORK/nr-out" 2>&1 || nr_rc=$?
check "a README with no region fails --write" "1" "$nr_rc"
if grep -q "table written" "$WORK/nr-out"; then bad "a README with no region still printed success"; else
    ok "a README with no region prints no success line"
fi

# ── mutants.sh: no room for the minimum budget refuses to start ───────────
mt="$WORK/mutants-mem"; mkdir -p "$mt/bin"
printf '#!/bin/sh\necho RAN "$@"\n' >"$mt/bin/cargo"; cp "$mt/bin/cargo" "$mt/bin/systemd-run"
chmod +x "$mt/bin/cargo" "$mt/bin/systemd-run"
printf 'MemTotal: 16777216 kB\nMemAvailable: 3145728 kB\n' >"$mt/meminfo"
mt_rc=0
(cd "$mt" && PATH="$mt/bin:$PATH" MUTANTS_MEMINFO="$mt/meminfo" "$ROOT/scripts/mutants.sh" --list) >"$mt/out" 2>&1 || mt_rc=$?
if [ "$mt_rc" -ne 0 ] && ! grep -q RAN "$mt/out"; then ok "3 GiB free under a 16 GiB reserve refuses to start"; else
    bad "3 GiB free under a 16 GiB reserve still started (rc=$mt_rc): $(head -c 300 "$mt/out")"
fi
check "the refusal says how to lower the reserve" "MUTANTS_RESERVE_GIB" "$(cat "$mt/out")"

# ── release-check: uncommitted source is refused before anything runs ────
rcr="$WORK/release-repo"; mkdir -p "$rcr/scripts" "$rcr/src" "$rcr/bin"
cp "$ROOT/scripts/release-check.sh" "$rcr/scripts/"
for s in gate.sh mutants.sh readme-compression.sh; do printf '#!/bin/sh\necho RAN %s\n' "$s" >"$rcr/scripts/$s"; chmod +x "$rcr/scripts/$s"; done
for s in gh make cargo rustup; do printf '#!/bin/sh\necho RAN %s\n' "$s" >"$rcr/bin/$s"; chmod +x "$rcr/bin/$s"; done
echo a >"$rcr/src/lib.rs"
git -C "$rcr" init -q && git -C "$rcr" add -A && git -C "$rcr" -c user.name=t -c user.email=t@example.invalid commit -qm init
echo b >"$rcr/src/lib.rs"
rcr_rc=0
PATH="$rcr/bin:$PATH" RELEASE_BASE=HEAD "$rcr/scripts/release-check.sh" >"$rcr/out" 2>&1 || rcr_rc=$?
if [ "$rcr_rc" -ne 0 ] && ! grep -q "RAN gate.sh" "$rcr/out"; then ok "release-check refuses uncommitted src/ before the gate"; else
    bad "release-check ran on uncommitted src/ (rc=$rcr_rc): $(head -c 300 "$rcr/out")"
fi

# ── --repin: a shape-only match is a suggestion, never a written move ─────
pr="$WORK/pins-repo"; mkdir -p "$pr/scripts" "$pr/src" "$pr/.cargo" "$pr/bin"
cp "$ROOT/scripts/check-mutants-pins.sh" "$pr/scripts/"
printf 'fn f() {\n    let a = 1;\n    a + b\n}\n' >"$pr/src/x.rs"
printf "exclude_re = [\n  '^src/x\\\\.rs:3:5: replace \\\\+ with \\\\* in f\$',\n]\n" >"$pr/.cargo/mutants.toml"
git -C "$pr" init -q && git -C "$pr" add -A && git -C "$pr" -c user.name=t -c user.email=t@example.invalid commit -qm init
# The equivalent line is removed; a look-alike is added under another guard.
printf 'fn f() {\n    let a = 1;\n    if g() {\n        a + b\n    }\n}\n' >"$pr/src/x.rs"
printf '#!/bin/sh\n[ "$1" = mutants ] && [ "$2" = --version ] && exit 0\necho "src/x.rs:4:5: replace + with * in f"\n' >"$pr/bin/cargo"; chmod +x "$pr/bin/cargo"
toml_before="$(sha256sum <"$pr/.cargo/mutants.toml")"
(cd "$pr" && PATH="$pr/bin:$PATH" ./scripts/check-mutants-pins.sh --repin) >"$pr/out" 2>&1
check "a shape-only match leaves mutants.toml as it was" "$toml_before" "$(sha256sum <"$pr/.cargo/mutants.toml")"
check "a shape-only match is printed for a reader" "suggest" "$(cat "$pr/out")"

# ── gate-measure.sh: baseline builds, perf samples, mutants outcomes ──────
# (lessence-65ct) Each fails closed: a failed step is never a number or a PASS.
gm_dir="$WORK/gm"; mkdir -p "$gm_dir/bin"
(
    # shellcheck source=scripts/gate-measure.sh
    . "$ROOT/scripts/gate-measure.sh"
    GATE_DIR="$gm_dir/gate"; base_target="$gm_dir/base-target"
    mkdir -p "$base_target/release"; echo stale >"$base_target/release/lessence"
    git() { [ "$1" = worktree ] && [ "$2" = add ] && mkdir -p "$4"; return 0; }
    cargo() { return 1; }
    if b="$(baseline_binary c0ffee base)"; then echo "returned:$b"; fi
    [ -e "$GATE_DIR/base-c0ffee/lessence" ] && echo "cached"
    echo done
) >"$gm_dir/bb.out" 2>/dev/null
if grep -q 'returned\|cached' "$gm_dir/bb.out"; then
    bad "a failed baseline build returns no path and caches nothing: $(tr '\n' ' ' <"$gm_dir/bb.out")"
else ok "a failed baseline build returns no path and caches nothing"; fi

# perf: stub taskset runs its command; stub perf prints what PERF_OUT says per
# call (one line per round in $gm_dir/perf-script) and exits PERF_RC.
cat >"$gm_dir/bin/taskset" <<'STUB'
#!/usr/bin/env bash
shift 2; exec "$@"
STUB
cat >"$gm_dir/bin/perf" <<'STUB'
#!/usr/bin/env bash
n=$(cat "$GM/count" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$GM/count"
line="$(sed -n "${n}p" "$GM/perf-script")"
rc="${line%% *}"; val="${line#* }"
[ "$val" = "-" ] || printf '%s\n' "$val" >&2
exit "$rc"
STUB
chmod +x "$gm_dir/bin/taskset" "$gm_dir/bin/perf"
perf_case() { # perf_case <name> <script lines...>: expects the measurement to fail
    local name="$1"; shift
    printf '%s\n' "$@" >"$gm_dir/perf-script"; rm -f "$gm_dir/count"
    if out="$(GM="$gm_dir" PATH="$gm_dir/bin:$PATH" bash -c '
        . "$1"; report_args() { :; }; GATE_CPU=0; PERF_CORPUS=/dev/null
        perf_instructions /bin/true' _ "$ROOT/scripts/gate-measure.sh" 2>/dev/null)"; then
        bad "$name (measured '$out')"
    else ok "$name"; fi
}
perf_case "a failed perf run is no measurement" "1 -" "1 -"
perf_case "a missing counter is no measurement" "0 1.0,msec,task-clock:u" "0 1.0,msec,task-clock:u"
perf_case "a not-counted counter is no measurement" "0 <not counted>,,cpu_core/instructions/u" "0 <not counted>,,cpu_core/instructions/u"
perf_case "a zero count is no measurement" "0 0,,cpu_core/instructions/u" "0 0,,cpu_core/instructions/u"
perf_case "a failed third round is no measurement" "0 1000,,cpu_core/instructions/u" "0 2000,,cpu_core/instructions/u" "1 -"
printf '%s\n' "0 1000,,cpu_core/instructions/u" "0 1001,,cpu_core/instructions/u" >"$gm_dir/perf-script"; rm -f "$gm_dir/count"
out="$(GM="$gm_dir" PATH="$gm_dir/bin:$PATH" bash -c '. "$1"; report_args() { :; }; GATE_CPU=0; PERF_CORPUS=/dev/null; perf_instructions /bin/true' _ "$ROOT/scripts/gate-measure.sh" 2>&1)"
check "two good rounds give their minimum" "1000 " "$out"

mut_case() { # mut_case <name> <rc> <outcomes json> <expected prefix>
    printf '%s' "$3" >"$gm_dir/outcomes.json"
    check "$1" "$4" "$( . "$ROOT/scripts/gate-measure.sh"; mutants_outcome "$2" "$gm_dir/outcomes.json")"
}
base_ok='{"scenario":"Baseline","summary":"Success"}'
mut() { printf '{"scenario":{"Mutant":{}},"summary":"%s"}' "$1"; }
mut_case "mutants timeouts are inconclusive" 3 "{\"outcomes\":[$base_ok,$(mut Timeout)]}" "broken"
mut_case "a timeout under exit 0 is inconclusive" 0 "{\"outcomes\":[$base_ok,$(mut CaughtMutant),$(mut Timeout)]}" "broken"
mut_case "exit 2 without a missed mutant is broken" 2 "{\"outcomes\":[$base_ok,$(mut CaughtMutant)]}" "broken"
mut_case "mutants without a successful baseline are broken" 0 "{\"outcomes\":[$(mut CaughtMutant)]}" "broken"
mut_case "an empty outcomes list under exit 2 is broken" 2 '{"outcomes":[]}' "broken"
mut_case "a missed mutant is counted" 2 "{\"outcomes\":[$base_ok,$(mut MissedMutant),$(mut CaughtMutant)]}" "ok 2 1"
mut_case "a clean run is counted" 0 "{\"outcomes\":[$base_ok,$(mut CaughtMutant),$(mut Unviable)]}" "ok 2 0"
check "no outcomes and no mutants.out is a genuine no-mutant run" "none" "$( . "$ROOT/scripts/gate-measure.sh"; mutants_outcome 0 "$gm_dir/absent/outcomes.json")"

# ── Helper scripts: a failing step leaves nothing of someone else's behind ─
rg_root="$WORK/rg-root"; mkdir -p "$rg_root/scripts" "$rg_root/target/release" "$rg_root/examples/distilled"
cp "$ROOT/scripts/record-goldens.sh" "$rg_root/scripts/"
printf '#!/usr/bin/env bash\nexit 3\n' >"$rg_root/target/release/lessence"; chmod +x "$rg_root/target/release/lessence"
echo x >"$rg_root/examples/distilled/k.log"
printf '1\tkeep\n' >"$rg_root/examples/distilled/k.golden"
"$rg_root/scripts/record-goldens.sh" k >/dev/null 2>&1
check "a failing run keeps the old golden" "keep" "$(cat "$rg_root/examples/distilled/k.golden")"
check "a failing run leaves no temp golden" "k.golden k.log" "$(cd "$rg_root/examples/distilled" && ls -A | tr '\n' ' ')"

distill_py="$(awk '/python3 -c .$/ {on=1; next} on && /^.$/ {exit} on' "$ROOT/scripts/distill.sh")"
check "the no-jq inventory of no groups is empty" "[]" "[$(printf '{"type":"summary"}\n' | python3 -c "$distill_py" 2>&1)]"
check "the no-jq inventory lists a group" "[3	a b]" "[$(printf '{"type":"group","count":3,"normalized":"a b"}\n' | python3 -c "$distill_py" 2>&1)]"

kind_dir="$WORK/kind-stub"; mkdir -p "$kind_dir"
printf '#!/usr/bin/env bash\ncase "$1" in create) echo "node(s) already exist for a cluster" >&2; exit 1;; delete) echo "$*" >>"%s/deleted";; esac\n' "$kind_dir" >"$kind_dir/kind"
chmod +x "$kind_dir/kind"
PATH="$kind_dir:$PATH" "$ROOT/scripts/capture-audit-log.sh" "$WORK/audit.log" >/dev/null 2>&1
check "a failed kind create deletes no cluster" "none" "$(cat "$kind_dir/deleted" 2>/dev/null || echo none)"

# ── The index the hook commits is the tree the gate built (lessence-65ct) ──
ix_repo="$WORK/ix-repo"
mkdir -p "$ix_repo/src"
(
    cd "$ix_repo" || exit 2
    git init -q .
    echo a >src/x.rs; echo doc >README.md
    git add -A
    git -c user.name=t -c user.email=t@example.invalid commit -q -m init
) >/dev/null 2>&1
ix() { (cd "$ix_repo" && "$ROOT/scripts/gate-diff-hash.sh" "$@" >/dev/null 2>&1); echo $?; }
echo b >"$ix_repo/src/x.rs"; git -C "$ix_repo" add src/x.rs
check "a fully staged source change matches the tree" "0" "$(ix --index-is-tree)"
echo c >"$ix_repo/src/x.rs"
check "a staged version unlike the one on disk is refused" "1" "$(ix --index-is-tree)"
git -C "$ix_repo" add src/x.rs
before_untracked="$(cd "$ix_repo" && "$ROOT/scripts/gate-diff-hash.sh")"
echo 'mod y;' >"$ix_repo/src/y.rs"
check "an untracked build input is refused" "1" "$(ix --index-is-tree)"
if [ "$(cd "$ix_repo" && "$ROOT/scripts/gate-diff-hash.sh")" != "$before_untracked" ]; then
    ok "an untracked build input moves the hash"; else bad "an untracked build input left the hash where it was"; fi
rm "$ix_repo/src/y.rs"
git -C "$ix_repo" commit -qm two -c user.name=t >/dev/null 2>&1 || git -C "$ix_repo" -c user.name=t -c user.email=t@example.invalid commit -qm two >/dev/null
check "a clean index changes no build input" "1" "$(ix --staged-inputs)"
echo x >"$ix_repo/README.md"; git -C "$ix_repo" add README.md
check "a staged non-input changes no build input" "1" "$(ix --staged-inputs)"
odd="$ix_repo/src/"$'t\tab ü*.rs'
echo z >"$odd"; git -C "$ix_repo" add -A
check "a staged source file with an unusual name is a build input" "0" "$(ix --staged-inputs)"
git -C "$ix_repo" -c user.name=t -c user.email=t@example.invalid commit -qm three >/dev/null
rm "$ix_repo/src/x.rs"; ln -s y.rs "$ix_repo/src/x.rs"; git -C "$ix_repo" add -A
check "a source file turned symlink is a build input" "0" "$(ix --staged-inputs)"
check "a git error is not 'no change'" "2" "$( (cd "$WORK" && "$ROOT/scripts/gate-diff-hash.sh" --staged-inputs >/dev/null 2>&1); echo $?)"

# ── The fold-review check reads the paths it is given, not the environment ─
fr="$WORK/fr"; mkdir -p "$fr"
echo '{"staged_diff_sha256":"s1","golden":[{"added":["x"],"removed":[],"recounted":[]}]}' >"$fr/changed.json"
echo '{"staged_diff_sha256":"s1","golden":[]}' >"$fr/quiet.json"
if GATE_JSON="$fr/quiet.json" REVIEW_JSON="$fr/none.json" "$ROOT/scripts/check-fold-review.sh" "$fr/changed.json" "$fr/none.json" >/dev/null 2>&1; then
    bad "an inherited GATE_JSON cannot stand in for the gate report the hook checked"
else ok "an inherited GATE_JSON cannot stand in for the gate report the hook checked"; fi

# ── A gate run retires the previous receipt before anything can fail ──────
rg="$WORK/rg"; mkdir -p "$rg/scripts" "$rg/target/gate"
cp "$ROOT/scripts/gate.sh" "$rg/scripts/"
echo '{"verdict": "PASS"}' >"$rg/target/gate/gate.json"
(cd "$rg" && bash scripts/gate.sh >/dev/null 2>&1)
if [ -e "$rg/target/gate/gate.json" ]; then bad "a gate run that stops early leaves no earlier PASS behind"; else
    ok "a gate run that stops early leaves no earlier PASS behind"; fi

# ── distill: the published log is the one that passed the scan ───────────
ds_root="$WORK/ds-root"; mkdir -p "$ds_root/scripts" "$ds_root/target/release" "$ds_root/examples/originals" "$ds_root/examples/distilled" "$ds_root/bin"
cp "$ROOT/scripts/distill.sh" "$ds_root/scripts/"
printf '#!/usr/bin/env bash\nexit 0\n' >"$ds_root/bin/cargo"; chmod +x "$ds_root/bin/cargo"
printf '#!/usr/bin/env bash\necho "fresh line"\n' >"$ds_root/target/release/lessence"; chmod +x "$ds_root/target/release/lessence"
echo "raw" >"$ds_root/examples/originals/k.log"
: >"$ds_root/vocab"
ds_run() { # ds_run <forbid regex> -> exit code; resets the earlier log first
    echo "earlier" >"$ds_root/examples/distilled/k.log"
    printf '%s\n' "$1" >"$ds_root/forbid"
    PATH="$ds_root/bin:$PATH" SCRUB_VOCAB="$ds_root/vocab" SCRUB_FORBID="$ds_root/forbid" \
        "$ds_root/scripts/distill.sh" >/dev/null 2>&1
}
ds_run 'fresh'; ds_rc=$?
check "distill: output holding a forbidden string is refused" "rc=1" "rc=$ds_rc"
check "distill: a refused output keeps the earlier log" "earlier" "$(cat "$ds_root/examples/distilled/k.log")"
check "distill: a refused output leaves no pending file" "[k.log]" "[$(cd "$ds_root/examples/distilled" && ls -A | tr '\n' ' ' | sed 's/ $//')]"
ds_run '('; ds_rc=$?
check "distill: a forbid list grep cannot read is refused" "rc=1" "rc=$ds_rc"
check "distill: an unreadable forbid list keeps the earlier log" "earlier" "$(cat "$ds_root/examples/distilled/k.log")"
ds_run '-absent'; ds_rc=$?
check "distill: a clean output replaces the earlier log" "rc=0 fresh line" "rc=$ds_rc $(cat "$ds_root/examples/distilled/k.log")"
check "release-check keeps scratch files in its own temporary directory" "0" "$(grep -c '/tmp/' "$ROOT/scripts/release-check.sh")"

# ── release-check scores mutants with the gate's judge (lessence-65ct) ────
rs_case() { # rs_case <name> <rc> <json> <expected substring>
    printf '%s' "$3" >"$gm_dir/rs-outcomes.json"
    check "$1" "$4" "$( . "$ROOT/scripts/gate-measure.sh"; mutation_score_of "$2" "$gm_dir/rs-outcomes.json" 2>&1)"
}
rs_ok='{"scenario":"Baseline","summary":"Success"}'
rs_case "release-check: exit 2 with no outcomes fails" 2 '{"outcomes":[]}' "failed"
rs_case "release-check: a string entry fails" 0 "{\"outcomes\":[$rs_ok,\"x\"]}" "failed"
rs_case "release-check: a timeout fails" 3 "{\"outcomes\":[$rs_ok,{\"scenario\":{\"Mutant\":{}},\"summary\":\"Timeout\"}]}" "failed"
rs_case "release-check: a complete run is scored" 2 "{\"outcomes\":[$rs_ok,{\"scenario\":{\"Mutant\":{}},\"summary\":\"CaughtMutant\"},{\"scenario\":{\"Mutant\":{}},\"summary\":\"MissedMutant\"}]}" "50.0 1 2"

echo "--- $fails failure(s)"
[ "$fails" -eq 0 ]
