#!/usr/bin/env bash
# Loopback consumer-reality check for CVE-2026-75614.  Expects `bash run.sh run`
# to have built the pinned runtimes/decoder in ./run first.  Builds
# consumer-service.c against the verbatim pinned runtimes, then exercises a
# natural (sizeof(Payload)==12) and an exact (9-byte) allocation on 127.0.0.1.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/run
SVC=$HERE/consumer-service.c
cd "$OUT" || exit 2
GEN=$OUT/build/gen
INC46="-I$OUT/build/v46/asn1crt -I$GEN"
INC47="-I$OUT/build/v47/asn1crt -I$GEN"

for kind in v46 v47; do
  INC=$([ "$kind" = v46 ] && echo "$INC46" || echo "$INC47")
  SRC="$OUT/build/$kind/asn1crt/"*.c
  gcc -g -O0 -Wall -fsanitize=address -fno-omit-frame-pointer $INC \
    "$SVC" "$GEN/schema.c" $SRC -o "$OUT/svc_${kind}_asan" || exit 2
  gcc -g -O0 -Wall $INC "$SVC" "$GEN/schema.c" $SRC \
    -o "$OUT/svc_${kind}_plain" || exit 2
done

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
PORT=39117
round() {
  local bin=$1 alloc=$2 count=$3 pattern=$4 tag=$5
  local log="$OUT/consumer-${tag}.log"
  "$bin" server "$alloc" "$PORT" "$count" "$pattern" > "$log" 2>&1 &
  local srv=$!
  sleep 0.3
  "$bin" client "$alloc" "$PORT" "$count" "$pattern" >> "$log" 2>&1
  wait "$srv"
  local rc=$?
  echo "=== $tag (rc=$rc) ==="
  cat "$log"
  echo
}

echo "### ASan, VULNERABLE 4.6.0.17 ###"
round "$OUT/svc_v46_asan" natural 7 0 v46_asan_natural7
round "$OUT/svc_v46_asan" exact   7 0 v46_asan_exact7
round "$OUT/svc_v46_asan" natural 2 0 v46_asan_natural2

echo "### ASan, FIXED 4.7.0.1 ###"
round "$OUT/svc_v47_asan" natural 7 0 v47_asan_natural7
round "$OUT/svc_v47_asan" exact   7 0 v47_asan_exact7

echo "### plain, VULNERABLE 4.6.0.17 (for gdb: gdb -x watch.gdb --args run/svc_v46_plain server natural PORT 7 0) ###"
round "$OUT/svc_v46_plain" natural 7 0 v46_plain_natural7
