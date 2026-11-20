#!/usr/bin/env bash
# FreeRDP GHSA-3m9q-g533-rqjq / CVE-2026-114045 file-only harness driver.
# No sockets, no network, no FreeRDP library: transcribed arithmetic + sink.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p logs
: > logs/summary.log

log() { printf '%s\n' "$*" | tee -a logs/summary.log; }
show() { sed 's/^/    /' "$1" | tee -a logs/summary.log; }

pass=1
record() { # record <description> <expected-rc> <name> <cmd...>
    local desc="$1" want="$2" name="$3"; shift 3
    local rc
    "$@" >"logs/${name}.out" 2>"logs/${name}.err"
    rc=$?
    log "--- ${name}: ${desc} (rc=${rc}, expected ${want})"
    show "logs/${name}.out"
    if [ -s "logs/${name}.err" ]; then
        printf '%s\n' "    [stderr]" | tee -a logs/summary.log
        show "logs/${name}.err"
    fi
    if [ "$rc" -ne "$want" ]; then
        log "FAIL: ${name} rc ${rc} != ${want}"
        pass=0
    fi
    return 0
}
expect() { # expect <file> <literal>  -- fail a check if literal absent
    if grep -Fq "$2" "$1"; then
        log "    ok: '$2'"
    else
        log "FAIL: '$2' not in $1"
        pass=0
    fi
}

log "=== FreeRDP GHSA-3m9q-g533-rqjq / CVE-2026-114045 file-only harness ==="
log "workspace: $(pwd)"

# --- build the three variants -----------------------------------------------
for spec in "vuln:" "fixed:-DBUILD_FIXED" "asan:-DBUILD_ASAN -fsanitize=address"; do
    name="${spec%%:*}"
    defs="${spec#*:}"
    # shellcheck disable=SC2086
    if ! gcc -g -O1 -fno-omit-frame-pointer -Wall $defs -o "$name" rdpsnd_overflow.c \
            >>logs/build.log 2>&1; then
        log "FAIL: build $name"
        show logs/build.log
        pass=0
    fi
done
if [ "$pass" -ne 1 ]; then
    log "CHECKS FAILED (build)"
    exit 1
fi

# --- rung 1: wraparound -> state corruption -> OOB write --------------------
record "nBlockAlign=4 nChannels=2 wraps bs, realloc fails, 7564-byte OOB" 0 rung1 ./vuln rung1
expect logs/rung1.out 'rc2=2 out_frames=0xfffffffffffffff0 realloc_failed=1'
expect logs/rung1.out 'oob_writes=7564 first_oob=8820 last_oob=16383'
expect logs/rung1.out '[rung1] RESULT=PASS'

# --- rung 2: chosen bytes at chosen OOB offsets -----------------------------
record "attacker sample bytes land verbatim at OOB offsets 8820 and 12000" 0 rung2 ./vuln rung2
expect logs/rung2.out 'oob=8820]=ab'
expect logs/rung2.out 'oob=12000]=cd'
expect logs/rung2.out '[rung2] RESULT=PASS'

# --- rung 3: ASan confirms the heap corruption at the CopyMemory sink -------
ASAN_OPTIONS='detect_leaks=0:allocator_may_return_null=1:abort_on_error=0:halt_on_error=1' \
    ./asan asan >logs/rung3-asan.out 2>&1
rc=$?
log "--- rung3: ASan heap-buffer-overflow at send_samples copy (rc=${rc}, expected 1)"
show logs/rung3-asan.out
if [ "$rc" -eq 1 ] && grep -Fq 'heap-buffer-overflow' logs/rung3-asan.out &&
   grep -Fq 'WRITE of size 16384' logs/rung3-asan.out &&
   grep -Fq '0 bytes after 8820-byte region' logs/rung3-asan.out; then
    log "    ok: ASan WRITE of size 16384, 0 bytes after 8820-byte region"
else
    log "FAIL: ASan signature mismatch"
    pass=0
fi

# --- rung 4: unbounded sequential attacker-controlled write -----------------
record "two SendSamples calls write chosen bytes at advancing OOB offsets" 0 rung4 ./vuln rung4
expect logs/rung4.out 'oob offset 8820  = de'
expect logs/rung4.out 'oob offset 21384 = ad'
expect logs/rung4.out 'out_pending_frames=8192'
expect logs/rung4.out '[rung4] RESULT=PASS'

# --- fixed build (real 3.32.1 guard) and benign control ---------------------
record "fixed 3.32.1 guard rejects the format, no OOB" 0 fixed ./fixed fixed
expect logs/fixed.out 'rc2=1 (want 1 INVALID_DATA) out_frames=2205'
expect logs/fixed.out 'oob_writes=0'
expect logs/fixed.out '[fixed] RESULT=PASS'
record "benign PCM control: no wrap, no OOB" 0 control ./vuln control
expect logs/control.out 'oob_writes=0'
expect logs/control.out '[control] RESULT=PASS'

# --- repeatability: 5/5 identical vulnerable traces -------------------------
for i in 1 2 3 4 5; do
    ./vuln rung1 >"logs/repeat-${i}.out" 2>/dev/null
    if ! cmp -s logs/repeat-1.out "logs/repeat-${i}.out"; then
        log "FAIL: repeat ${i} differs"
        pass=0
    fi
done
log "repeatability: 5 vulnerable rung1 traces byte-identical"

# --- pinned digests ---------------------------------------------------------
{
    sha256sum rdpsnd_overflow.c
    sha256sum run.sh
} > logs/digests.txt
log "--- pinned digests (logs/digests.txt)"
show logs/digests.txt

if [ "$pass" -eq 1 ]; then
    log "ALL CHECKS PASS"
else
    log "CHECKS FAILED"
fi
exit $((1 - pass))
