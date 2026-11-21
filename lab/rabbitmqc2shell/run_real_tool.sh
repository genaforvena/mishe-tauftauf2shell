#!/usr/bin/env bash
# Consumer-reality negative result for CVE-2026-61547:
# the REAL shipped amqp-publish tool (high-level amqp_basic_publish path)
# does NOT overflow on pinned v0.16.0, because bodies are chunked to
# frame_max - 12 and amqp_tune_connection resizes the buffer to frame_max.
# All traffic stays on 127.0.0.1. Requires cmake, gcc, python3, apt download.
set -u
OUT="${1:-/tmp/rmq2-real-tool}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../frontier/rabbitmqc2shell/src"
rm -rf "$OUT"
mkdir -p "$OUT"

pass=0
fail=0
check() {
  if [ "$2" = "0" ]; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi
}

# 1. pinned sources
(cd "$SRC" && sha256sum -c SHA256SUMS) >"$OUT/pins.log" 2>&1
check "six upstream pins" $?

# 2. provision popt dev headers locally (no root)
(cd "$OUT" && apt-get download libpopt-dev >/dev/null 2>&1 && \
  mkdir -p popt-dev && dpkg-deb -x libpopt-dev_*.deb popt-dev)
check "popt dev headers provisioned" $?
POPTDEV="$OUT/popt-dev/usr"
[ -f "$POPTDEV/include/popt.h" ]
check "popt.h present" $?

# 3. pinned 0.16.0 + real tools, ASan
mkdir -p "$OUT/src"
tar xzf "$SRC/0.16.0.tar.gz" -C "$OUT/src"
cmake -S "$OUT/src/rabbitmq-c-0.16.0" -B "$OUT/build" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address -g -O0 -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
  -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
  -DCMAKE_PREFIX_PATH="$POPTDEV" \
  -DBUILD_TOOLS=ON -DBUILD_EXAMPLES=OFF -DENABLE_SSL_SUPPORT=OFF \
  >"$OUT/cmake.log" 2>&1
check "cmake configure" $?
cmake --build "$OUT/build" -j4 >"$OUT/build.log" 2>&1
check "ASan build of real amqp-publish" $?
[ -x "$OUT/build/tools/amqp-publish" ]
check "amqp-publish binary exists" $?

# 4. real tool, 200000-byte chosen body through fake loopback broker
RMQ2_TOOL="$OUT/build/tools/amqp-publish" \
RMQ2_LIBDIR="$OUT/build/librabbitmq" \
RMQ2_POPTDIR="$POPTDEV" \
RMQ2_LOG="$OUT/tool.log" \
RMQ2_PORT=15680 \
RMQ2_BODY_LEN=200000 \
python3 "$HERE/real_tool_probe.py" >"$OUT/probe.out" 2>&1
check "real tool run rc 0" $?
grep -q "'handshake': 'complete'" "$OUT/probe.out"
check "full AMQP handshake completed" $?
grep -q "'header': '414d515000000901'" "$OUT/probe.out"
check "client sent AMQP 0-9-1 header" $?
if grep -q 'AddressSanitizer' "$OUT/tool.log"; then r=1; else r=0; fi
check "no ASan report from high-level publish path" $r
nbody=$(python3 -c '
import ast,re,sys
s=open(sys.argv[1]).read()
line=[l for l in s.splitlines() if l.startswith("result ")][0]
r=ast.literal_eval(line[len("result "):])
print(sum(1 for f in r.get("frames",[]) if f[1]==3))
' "$OUT/probe.out")
[ "$nbody" = "2" ]
check "body chunked into exactly two BODY frames (131060 + 68940)" $?

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" = 0 ]
