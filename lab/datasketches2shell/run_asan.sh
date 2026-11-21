#!/usr/bin/env bash
# Boot the loopback service under ASan, send the 264-byte count-64 image,
# capture the report and assert the library frames appear in the service.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
PORT=${2:-38117}
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
python3 "$HERE/drive.py" --bin "$OUT/service_asan" --port "$PORT" \
  --count 64 --value 90 --seed "$OUT/seed.bin" > "$OUT/service_asan.log" 2>&1
log=$(cat "$OUT/service_asan.log")
printf '%s\n' "$log"
ok=1
case "$log" in *'heap-buffer-overflow'*) : ;; *) ok=0;; esac
case "$log" in *'WRITE of size 256'*) : ;; *) ok=0;; esac
case "$log" in *'CouponList-internal.hpp:116'*) : ;; *) ok=0;; esac
case "$log" in *'HllSketchImplFactory.hpp:101'*) : ;; *) ok=0;; esac
case "$log" in *'HllSketch-internal.hpp:63'*) : ;; *) ok=0;; esac
case "$log" in *'SERVICE_LISTEN'*) : ;; *) ok=0;; esac
if [ "$ok" -eq 1 ]; then echo "LOOPBACK_ASAN_PASS"; exit 0; fi
echo "LOOPBACK_ASAN_FAIL"; exit 1
