#!/usr/bin/env bash
# Reproduce the SIZE(0..17) rung-4 boundary: chosen bytes in live malloc metadata.
# Expects `bash run.sh run` first (pinned runtimes + compiler under ./run).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/run
cd "$HERE" || exit 2

mkdir -p "$OUT/gen-v17"
printf 'TEST DEFINITIONS ::= BEGIN\nPayload ::= OCTET STRING (SIZE(0..17))\nEND\n' \
  > "$OUT/gen-v17/schema.asn"
(cd "$OUT/gen-v17" && ../build/asn1scc/asn1scc -c -uPER schema.asn) \
  > "$OUT/codegen-v17.log" 2>&1 || exit 2

INC="-I$OUT/gen-v17 -I$OUT/build/v46/asn1crt"
gcc -g -O0 -Wall -fsanitize=address -fno-omit-frame-pointer $INC \
  "$HERE/variant-service.c" "$OUT/gen-v17/schema.c" "$OUT/build/v46/asn1crt/"*.c \
  -o "$OUT/variant_asan" || exit 2
gcc -g -O0 -Wall $INC "$HERE/variant-service.c" "$OUT/gen-v17/schema.c" \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/variant_plain" || exit 2
FIX="-I$OUT/gen-v17 -I$OUT/build/v47/asn1crt"
gcc -g -O0 -Wall -fsanitize=address -fno-omit-frame-pointer $FIX \
  "$HERE/variant-service.c" "$OUT/gen-v17/schema.c" "$OUT/build/v47/asn1crt/"*.c \
  -o "$OUT/variant_fixed_asan" || exit 2

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
round() {
  local bin=$1 port=$2 count=$3 tag=$4
  "$bin" server "$port" "$count" 0 > "$OUT/variant-${tag}.log" 2>&1 &
  local srv=$!
  sleep 0.3
  "$bin" client "$port" "$count" 0 >> "$OUT/variant-${tag}.log" 2>&1
  wait "$srv"
  echo "=== $tag (rc=$?) ==="
  grep -E 'ERROR: AddressSanitizer|WRITE of size|located|Payload_Decode|svc sizeof|decoded=' \
    "$OUT/variant-${tag}.log"
  echo
}
round "$OUT/variant_asan" 39261 2  benign
round "$OUT/variant_asan" 39262 31 hostile
round "$OUT/variant_fixed_asan" 39263 31 fixed_control

echo "### gdb watchpoint on live next-chunk size field (obj+24) ###"
gdb -q -batch -x "$HERE/watch-variant.gdb" \
  --args "$OUT/variant_plain" server 39264 31 0 > "$OUT/gdb-variant.log" 2>&1 &
local_gdb=$!
sleep 1.5
"$OUT/variant_plain" client 39264 31 0 >> "$OUT/gdb-variant.log" 2>&1
wait "$local_gdb"
grep -E 'BREAK:|PRE next|WATCH HIT|POST next|chosen at' "$OUT/gdb-variant.log"
