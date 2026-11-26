#!/usr/bin/env bash
# nfdump2shell: live loopback test of the receive-allocation boundary.
# A maximum-size IPv4 UDP datagram (65507 B) places a zero-length
# EXgenericFlow element at the very end of recvfrom()'s 65535-byte buffer.
# The pinned msecReceived store then lands at 65523..65530 -- four bytes
# inside the allocation -- while later struct reads cross the end.
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${EDGE_OUT:-harness/out/edge}
if [ ! -x "$V/nfcapd/nfcapd" ] || [ ! -x "$F/nfcapd/nfcapd" ] || [ ! -x "$VP/nfcapd/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT"

PASS=0; FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
need() {
    if grep -qa "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi
}
none() {
    if grep -qa "$2" "$1" 2>/dev/null; then bad "$3"; else ok "$3"; fi
}

run_case() { # LABEL BUILD PORT MODE
    local label=$1 build=$2 port=$3 mode=$4
    local dir="$OUT/$label"
    rm -rf "$dir"; mkdir -p "$dir/flows"
    ASAN_OPTIONS=detect_leaks=0 "$build/nfcapd/nfcapd" \
        -4 -b 127.0.0.1 -p "$port" -M "$dir/flows" -t 5 >"$dir/daemon.log" 2>&1 &
    local pid=$!
    sleep 1
    python3 harness/wire_send.py "$port" "$mode" >"$dir/sender.log" 2>&1
    sleep 1
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    local cap
    cap=$(find "$dir/flows" -type f | sort | head -1)
    if [ -n "$cap" ]; then
        ASAN_OPTIONS=detect_leaks=0 "$build/nfdump/nfdump" -r "$cap" \
            -o 'fmt:%ts|%sp|%dp|%pr|%pkt|%byt' >"$dir/flows.txt" 2>&1 || true
    fi
    echo "=== $label mode=$mode ==="
    head -1 "$dir/sender.log"
    grep -aE 'AddressSanitizer|READ of size|WRITE of size|Corrupt nfd record' "$dir/daemon.log" | head -6 || true
    grep -aE '^Summary: total flows' "$dir/flows.txt" 2>/dev/null || true
}

run_case edge-vuln-asan "$V" 10111 edge; D="$OUT/edge-vuln-asan"
need "$D/sender.log" 'WIRE_LEN=65507' 'edge: maximum IPv4 UDP payload'
need "$D/daemon.log" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'vuln ASan: live overflow from the short element'
need "$D/daemon.log" 'READ of size' 'vuln ASan: crossing access is a read, not the 8-byte store'
need "$D/daemon.log" 'nfd_raw.c' 'vuln ASan: fault inside pinned Process_nfd'

run_case edge-safe-asan "$V" 10113 edge-safe; D="$OUT/edge-safe-asan"
need "$D/sender.log" 'WIRE_LEN=65507' 'safe: same datagram size'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'safe: complete element stays inside allocation'
run_case edge-fixed-asan "$F" 10114 edge; D="$OUT/edge-fixed-asan"
need "$D/daemon.log" 'Corrupt nfd record' 'fixed: short element rejected live'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'fixed: no overflow'

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
