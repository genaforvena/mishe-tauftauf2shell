#!/bin/bash
# One crafted SNMP GET to a plant-started ASan mini-snmpd on 127.0.0.1:16161.
# No external address, no scan, no bulk mode. The daemon is killed on exit.
set -u
cd "$(dirname "$0")" || exit 99
B=mini-snmpd-b532243732609cf7af58ceb1794a0adfe8deeff1
PORT=16161
rm -f asan.* daemon.out crafted.bin
python3 mkpkt.py crafted.bin || exit 98

( cd "$B" || exit 98
  exec env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:log_path=../asan \
       ./mini-snmpd -n -p "$PORT" -l debug ) > daemon.out 2>&1 &
pid=$!
sleep 1
python3 - "$PORT" <<'PY'
import socket, sys
data = open("crafted.bin", "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(data, ("127.0.0.1", int(sys.argv[1])))
print(f"WIRE_SENT_BYTES={len(data)} DEST=127.0.0.1:{sys.argv[1]}")
PY
sleep 2
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
printf 'DAEMON_PID=%s\n' "$pid"
printf -- '--- daemon.out ---\n'
head -25 daemon.out
printf -- '--- asan log ---\n'
for f in asan.*; do
    [ -f "$f" ] || continue
    printf -- '--- %s ---\n' "$f"
    head -40 "$f"
done
