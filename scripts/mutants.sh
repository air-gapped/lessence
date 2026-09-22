#!/usr/bin/env bash
# cargo mutants, sized to the memory this machine has free right now.
#
#   scripts/mutants.sh <cargo mutants args...>
#
# This machine is a workstation, not a build box: a browser, an editor and
# whatever else is open have to survive the run. Budget from what is FREE
# right now, not from a number somebody picked when the machine was idle —
# `MemoryMax=48G` on a 62 GiB box with 39 GiB already in use is not a cap,
# it is permission to take everything, and the kernel pays for it by
# evicting the desktop.
#
# Overrides: MUTANTS_RESERVE_GIB (left for everything that is not this run,
# default 16), MUTANTS_MEM_MAX (e.g. 20G), MUTANTS_JOBS, MUTANTS_TIMEOUT_MULT.
set -euo pipefail

MUTANTS_RESERVE_GIB="${MUTANTS_RESERVE_GIB:-16}"
MUTANTS_TIMEOUT_MULT="${MUTANTS_TIMEOUT_MULT:-3}"
avail_gib="$(awk '/^MemAvailable:/ {printf "%d", $2/1048576}' /proc/meminfo)"
budget_gib=$(( avail_gib - MUTANTS_RESERVE_GIB ))
[ "$budget_gib" -lt 4 ] && budget_gib=4
MUTANTS_MEM_MAX="${MUTANTS_MEM_MAX:-${budget_gib}G}"
budget_gib="${MUTANTS_MEM_MAX%G}"

# Each worker is a full cargo build tree. Memory, not cores, is what runs
# out first, so the worker count comes from the budget and what one worker
# took last time: the previous run's anonymous-memory peak divided by its
# jobs, plus a quarter. Page cache is not counted; the kernel reclaims it
# before it kills anything. The first run on a machine has no record and
# assumes 4 GiB.
mem_record="target/gate/mutants-mem"
mkdir -p "$(dirname "$mem_record")"
per_job_mib=4096
if [ -r "$mem_record" ]; then
    read -r peak_mib ran_jobs < "$mem_record" || true
    if [ "${ran_jobs:-0}" -gt 0 ] 2>/dev/null; then
        per_job_mib=$(( peak_mib / ran_jobs * 5 / 4 ))
        [ "$per_job_mib" -lt 1024 ] && per_job_mib=1024
    fi
fi
jobs=$(( budget_gib * 1024 / per_job_mib ))
[ "$jobs" -lt 1 ] && jobs=1
cores="$(nproc)"
[ "$jobs" -gt "$cores" ] && jobs="$cores"
[ "$jobs" -gt 8 ] && jobs=8
MUTANTS_JOBS="${MUTANTS_JOBS:-$jobs}"

echo "mutants budget: ${MUTANTS_MEM_MAX} of ${avail_gib}G available, ${MUTANTS_JOBS} jobs at ${per_job_mib} MiB each (reserve ${MUTANTS_RESERVE_GIB}G)" >&2
if [ "$MUTANTS_JOBS" -le 1 ]; then
    echo "  only ${avail_gib}G free, so this runs single-job and will be slow." >&2
    echo "  Close what you can, or lower the reserve deliberately:" >&2
    echo "    MUTANTS_RESERVE_GIB=8 $0 ..." >&2
fi

# Each worker copies the tree, build output included, into TMPDIR. /tmp is
# tmpfs here: eight copies filled its 32G quota and are RAM besides, so the
# copies go to disk.
export TMPDIR="${MUTANTS_TMPDIR:-/var/tmp}"

# A run with fewer mutants than jobs keeps only that many workers busy, and
# its peak must be divided by those, not by -j, or the next run oversizes.
mutant_count="$(cargo mutants --list "$@" 2>/dev/null | wc -l)"
busy=$(( mutant_count < MUTANTS_JOBS ? mutant_count : MUTANTS_JOBS ))
[ "$busy" -lt 1 ] && busy=1

# A user-scope unit caps memory without a polkit prompt, so the run also
# works from a non-interactive session. MemoryHigh is the budget: past it
# the kernel reclaims and throttles the run instead of killing it, so an
# underestimate costs time, not a worker. MemoryMax is the hard stop 2 GiB
# above, taken from the reserve. The scope records its anonymous peak for
# the next run's sizing.
exec systemd-run --user --scope -q -p "MemoryHigh=${MUTANTS_MEM_MAX}" \
    -p "MemoryMax=$(( budget_gib + 2 ))G" nice -n 19 \
    bash -c '
        cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
        peak=0
        ( while sleep 2; do
            a=$(awk "/^anon /{print int(\$2/1048576)}" "$cg/memory.stat")
            [ "$a" -gt "$peak" ] && peak=$a && echo "$peak $1" > "$2"
          done ) &
        sampler=$!
        shift 2
        rc=0
        env PROPTEST_CASES=32 PROPTEST_MAX_SHRINK_ITERS=100 cargo mutants "$@" || rc=$?
        kill "$sampler"
        exit "$rc"' _ "$busy" "$mem_record" \
    -j "$MUTANTS_JOBS" --timeout-multiplier "$MUTANTS_TIMEOUT_MULT" "$@"
