#!/usr/bin/env bash
# nfdump2shell: drive the pinned nfcapd receive path over a real loopback UDP
# socket. Vulnerable/fixed collectors, attack/safe/icmp/single datagrams.
# Works with either ASan or plain builds (V_BUILD / F_BUILD). No external host,
# no command execution.
set -u
cd "$(dirname "$0")"
V=${V_BUILD:-src/build-vuln-asan/src}
F=${F_BUILD:-src/build-fixed-asan/src}
OUT=${WIRE_OUT:-harness/out/wire}
if [ ! -x "$V/nfcapd/nfcapd" ] || [ ! -x "$F/nfcapd/nfcapd" ]; then
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
    LAST_DIR="$OUT/$label"
    local dir="$LAST_DIR"
    rm -rf "$dir"; mkdir -p "$dir/flows"
    ASAN_OPTIONS=detect_leaks=0 "$build/nfcapd/nfcapd" \
        -4 -b 127.0.0.1 -p "$port" -M "$dir/flows" -t 5 -v 3 \
        >"$dir/daemon.log" 2>&1 &
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
    echo "=== $label mode=$mode cap=${cap:-NONE} ==="
    head -2 "$dir/sender.log"
    grep -E 'Corrupt nfd record|record size error|ERROR: AddressSanitizer' "$dir/daemon.log" || true
    grep -E '^Summary: total flows' "$dir/flows.txt" 2>/dev/null || true
}

D=''
run_case vuln-attack "$V" 10081 attack; D=$LAST_DIR
need "$D/sender.log" 'WIRE_LEN=112' 'attack wire length 112'
need "$D/daemon.log" 'record size error' 'live: next record header clobbered'
need "$D/flows.txt" 'total flows: 1' 'live: vulnerable collector writes 1 flow'
none "$D/daemon.log" 'ERROR: AddressSanitizer' 'attack: no ASan report in 64 KiB buffer'

run_case vuln-safe "$V" 10082 safe; D=$LAST_DIR
need "$D/flows.txt" 'total flows: 2' 'safe: vulnerable collector writes 2 flows'
need "$D/flows.txt" '|       5|     500' 'safe: both chosen flow values survive'

run_case vuln-icmp "$V" 10083 icmp; D=$LAST_DIR
need "$D/daemon.log" 'record size error' 'icmp: next record header clobbered'
need "$D/flows.txt" 'total flows: 1' 'icmp: vulnerable collector writes 1 flow'

run_case vuln-single "$V" 10084 single; D=$LAST_DIR
need "$D/sender.log" 'WIRE_LEN=48' 'single: 48-byte datagram on wire'
need "$D/flows.txt" 'total flows: 1' 'single: truncated record still written'

run_case fixed-attack "$F" 10085 attack; D=$LAST_DIR
need "$D/daemon.log" 'Corrupt nfd record: expected 2 records, processd: 0' 'fixed: short element rejected live'
need "$D/flows.txt" 'total flows: 0' 'fixed: no flow written for attack'

run_case fixed-safe "$F" 10086 safe; D=$LAST_DIR
need "$D/flows.txt" 'total flows: 2' 'fixed: safe datagram still yields 2 flows'



printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
