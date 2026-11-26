#!/usr/bin/env bash
# nfdump2shell: live loopback IPv6 test of the receive-allocation boundary.
# IPv4 caps a UDP datagram at 65507 B, leaving the truncated-element store
# inside in_buff.  On ::1 a 65527 B datagram is accepted; a terminal 4-byte
# EXgenericFlow element then writes msecReceived at 65543..65550, eight bytes
# past the 65535-byte allocation.  ASan sees the WRITE in Process_nfd; the
# genuine plain collector aborts in glibc heap validation at shutdown.
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
VP=${V_PLAIN:-src/build-vuln-plain/src}
FP=${F_PLAIN:-src/build-fixed-plain/src}
OUT=${V6_OUT:-harness/out/v6edge}
if [ ! -x "$V/nfcapd/nfcapd" ] || [ ! -x "$F/nfcapd/nfcapd" ] || \
   [ ! -x "$VP/nfcapd/nfcapd" ] || [ ! -x "$FP/nfcapd/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT"

PASS=0; FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
need() { if grep -qa "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }
need_re() { if grep -qaE "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }
none() { if grep -qaE "$2" "$3" 2>/dev/null; then bad "$1"; else ok "$1"; fi; }

run_case() { # LABEL BUILD PORT MODE
    local label=$1 build=$2 port=$3 mode=$4
    local dir="$OUT/$label"
    rm -rf "$dir"; mkdir -p "$dir/flows"
    ASAN_OPTIONS=detect_leaks=0 "$build/nfcapd/nfcapd" \
        -6 -b ::1 -p "$port" -M "$dir/flows" -t 5 >"$dir/daemon.log" 2>&1 &
    local pid=$!
    sleep 1
    python3 harness/wire_send.py "$port" "$mode" >"$dir/sender.log" 2>&1
    sleep 1
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    echo "$?" >"$dir/rc.txt"
    local cap
    cap=$(find "$dir/flows" -type f | sort | head -1)
    if [ -n "$cap" ]; then
        ASAN_OPTIONS=detect_leaks=0 "$build/nfdump/nfdump" -r "$cap" \
            -o 'fmt:%ts|%sp|%dp|%pr|%pkt|%byt' >"$dir/flows.txt" 2>&1 || true
    fi
    echo "=== $label mode=$mode rc=$(cat "$dir/rc.txt") ==="
    head -1 "$dir/sender.log"
    grep -aE 'AddressSanitizer|WRITE of size|Corrupt nfd record|free\(\)|double free' "$dir/daemon.log" | head -6 || true
    grep -aE '^Summary: total flows' "$dir/flows.txt" 2>/dev/null || true
}

run_case v6-vuln-asan-attack "$V" 10241 v6edge; D="$OUT/v6-vuln-asan-attack"
need 'v6: maximum IPv6 UDP payload' 'WIRE_LEN=65527' "$D/sender.log"
need 'vuln ASan: live heap overflow' 'ERROR: AddressSanitizer: heap-buffer-overflow' "$D/daemon.log"
need 'vuln ASan: 8-byte store, not the read' 'WRITE of size 8' "$D/daemon.log"
need 'vuln ASan: crosses the 65535-byte receive allocation' '65535-byte region' "$D/daemon.log"
need 'vuln ASan: fault inside pinned Process_nfd' 'nfd_raw.c:256' "$D/daemon.log"
need 'vuln ASan: allocation is in_buff from nfcapd.c:273' 'nfcapd.c:273' "$D/daemon.log"

run_case v6-vuln-asan-safe "$V" 10242 v6edge-safe; D="$OUT/v6-vuln-asan-safe"
need 'v6 safe: same datagram size' 'WIRE_LEN=65527' "$D/sender.log"
none 'v6 safe: complete element leaves the allocation intact' 'ERROR: AddressSanitizer' "$D/daemon.log"

run_case v6-fixed-asan-attack "$F" 10243 v6edge; D="$OUT/v6-fixed-asan-attack"
need 'v6 fixed: short element rejected live' 'Corrupt nfd record' "$D/daemon.log"
none 'v6 fixed: no ASan report' 'ERROR: AddressSanitizer' "$D/daemon.log"

run_case v6-vuln-plain-attack "$VP" 10244 v6edge; D="$OUT/v6-vuln-plain-attack"
need 'v6 plain: SIGABRT from heap metadata corruption' '^134$' "$D/rc.txt"
need_re 'v6 plain: glibc detects the corrupted chunk' 'double free or corruption|free\(\): invalid next size' "$D/daemon.log"

run_case v6-vuln-plain-safe "$VP" 10245 v6edge-safe; D="$OUT/v6-vuln-plain-safe"
need 'v6 plain safe: daemon exits normally' '^0$' "$D/rc.txt"
none 'v6 plain safe: no heap corruption' 'double free or corruption|free\(\): invalid next size' "$D/daemon.log"

run_case v6-fixed-plain-attack "$FP" 10246 v6edge; D="$OUT/v6-fixed-plain-attack"
need 'v6 plain fixed: daemon exits normally' '^0$' "$D/rc.txt"
need 'v6 plain fixed: short element rejected' 'Corrupt nfd record' "$D/daemon.log"
none 'v6 plain fixed: no heap corruption' 'double free or corruption|free\(\): invalid next size' "$D/daemon.log"

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
