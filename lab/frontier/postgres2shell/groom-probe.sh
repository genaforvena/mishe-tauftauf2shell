#!/bin/bash
# Run inside the PTRACE-capable pg2shell-gdb container (127.0.0.1 only).
# Usage: docker cp the three groom files into /tmp, then: bash /tmp/groom-probe.sh
set -u
cd /tmp
rm -f sqlgroom psqlgroom.out gdbgroom.out
mkfifo sqlgroom
psql -U postgres -h 127.0.0.1 -a -q < sqlgroom > psqlgroom.out 2>&1 &
PSQLPID=$!
exec 3>sqlgroom
printf 'SELECT pg_backend_pid();\n' >&3
for i in $(seq 1 30); do
  grep -qE '^[[:space:]]*[0-9]+[[:space:]]*$' psqlgroom.out && break
  sleep 0.2
done
BPID=$(grep -oE '^[[:space:]]*[0-9]+[[:space:]]*$' psqlgroom.out | head -1 | tr -d ' ')
echo "backend pid=$BPID"
if [ -z "$BPID" ]; then echo "NO BACKEND PID"; exec 3>&-; kill $PSQLPID 2>/dev/null; exit 1; fi
gdb -q -batch -p "$BPID" -x gdbgroom.cmd > gdbgroom.out 2>&1 &
GPID=$!
sleep 3
cat trigger-groom.sql >&3
for i in $(seq 1 60); do
  kill -0 "$GPID" 2>/dev/null || break
  sleep 0.5
done
if kill -0 "$GPID" 2>/dev/null; then
  echo "gdb still attached after 30s; killing backend to release"
  kill -9 "$BPID" 2>/dev/null
  sleep 2
fi
kill -0 "$GPID" 2>/dev/null && kill -9 "$GPID" 2>/dev/null
exec 3>&-
kill "$PSQLPID" 2>/dev/null
echo "=== GDB OUT ==="
cat gdbgroom.out
echo "=== PSQL OUT ==="
cat psqlgroom.out
