#!/bin/bash
# Safe wire control: an in-bounds SNMP GET to plant-started vulnerable and
# fixed mini-snmpd instances on loopback ports 16163/16164 only.
set -u
cd "$(dirname "$0")" || exit 99
VULN=mini-snmpd-b532243732609cf7af58ceb1794a0adfe8deeff1
FIXED=mini-snmpd-5419bc3816a09b7a2ca38c47f0888ad01c8fe897
python3 mksafe.py safe.bin || exit 98

for spec in "vuln:$VULN:16163" "fixed:$FIXED:16164"; do
    name=${spec%%:*}
    rest=${spec#*:}
    tree=${rest%%:*}
    port=${rest##*:}
    out="safe-${name}.out"
    rm -f "$out"
    ( cd "$tree" || exit 98
      exec env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
           ./mini-snmpd -n -p "$port" -l debug ) > "$out" 2>&1 &
    pid=$!
    sleep 1
    python3 - "$port" <<'PY'
import socket, sys
data = open("safe.bin", "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(data, ("127.0.0.1", int(sys.argv[1])))
print(f"SAFE_SENT_BYTES={len(data)} DEST=127.0.0.1:{sys.argv[1]}")
PY
    sleep 2
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    printf -- '--- %s (pid %s) ---\n' "$name" "$pid"
    head -20 "$out"
done
