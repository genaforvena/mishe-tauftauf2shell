#!/usr/bin/env bash
# Verify the frontier pins, extract pinned 5.2.0 verbatim, build the loopback
# consumer (ASan and plain) and emit a real compact seed image.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
PIN=${PIN:-"$HERE/../frontier/datasketches2shell"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

(cd "$PIN/src" && sha256sum -c SHA256SUMS) > "$OUT/pins.log" 2>&1 || { cat "$OUT/pins.log"; exit 2; }
rm -rf "$OUT/v52"
mkdir -p "$OUT/v52"
tar -xzf "$PIN/src/5.2.0.tar.gz" -C "$OUT/v52" --strip-components=1 || exit 2
I52="-I$OUT/v52/hll/include -I$OUT/v52/common/include"

g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I52 \
  "$HERE/service.cpp" -o "$OUT/service_asan" || exit 2
g++ -std=c++11 -O0 -g $I52 "$HERE/service.cpp" -o "$OUT/service_plain" || exit 2
g++ -std=c++11 -O0 -g $I52 "$HERE/seedgen.cpp" -o "$OUT/seedgen" || exit 2
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I52 \
  "$HERE/stream_service.cpp" -o "$OUT/stream_service_asan" || exit 2
g++ -std=c++11 -O0 -g $I52 "$HERE/stream_service.cpp" -o "$OUT/stream_service_plain" || exit 2
"$OUT/seedgen" "$OUT/seed.bin" || exit 2
echo "BUILD_OK pins=$(wc -l < "$OUT/pins.log") seed=$(stat -c %s "$OUT/seed.bin")"
