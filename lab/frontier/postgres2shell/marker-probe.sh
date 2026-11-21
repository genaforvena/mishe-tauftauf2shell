#!/bin/bash
# Run inside the PTRACE-capable pg2shell-gdb container (127.0.0.1 only).
# Usage: docker cp the two marker files into /tmp, then: bash /tmp/marker-probe.sh
set -u
cd /tmp
rm -f sqlmark psqlmark.out gdbmark.out
mkfifo sqlmark
psql -U postgres -h 127.0.0.1 -a -q < sqlmark > psqlmark.out 2>&1 &
PSQLPID=$!
exec 3>sqlmark
printf 'SELECT pg_backend_pid();\n' >&3
for i in $(seq 1 30); do
  grep -qE '^[[:space:]]*[0-9]+[[:space:]]*$' psqlmark.out && break
  sleep 0.2
done
BPID=$(grep -oE '^[[:space:]]*[0-9]+[[:space:]]*$' psqlmark.out | head -1 | tr -d ' ')
echo "backend pid=$BPID"
if [ -z "$BPID" ]; then echo "NO BACKEND PID"; exec 3>&-; kill $PSQLPID 2>/dev/null; exit 1; fi
gdb -q -batch -p "$BPID" -x gdbmark.cmd > gdbmark.out 2>&1 &
GPID=$!
sleep 3
cat trigger-marker.sql >&3
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
cat gdbmark.out
echo "=== PSQL OUT ==="
cat psqlmark.out
