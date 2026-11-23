#!/bin/bash
# Fixed control: same crafted datagram to a plant-started ASan mini-snmpd
# built at fix commit 5419bc38, on loopback 127.0.0.1:16162 only.
set -u
cd "$(dirname "$0")" || exit 99
B=mini-snmpd-5419bc3816a09b7a2ca38c47f0888ad01c8fe897
PORT=16162
rm -f fixed-asan.* fixed-daemon.out crafted.bin
python3 mkpkt.py crafted.bin || exit 98

( cd "$B" || exit 98
  exec env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:log_path=../fixed-asan \
       ./mini-snmpd -n -p "$PORT" -l debug ) > fixed-daemon.out 2>&1 &
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
printf -- '--- fixed-daemon.out ---\n'
head -25 fixed-daemon.out
printf -- '--- fixed asan log ---\n'
for f in fixed-asan.*; do
    [ -f "$f" ] || continue
    printf -- '--- %s ---\n' "$f"
    head -40 "$f"
done
