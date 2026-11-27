#!/bin/sh
# Frontier runner: pinned vulnerable vs fixed OpenJPH HT cleanup allocation.
# PASS counts are assertions, not a claim of rung 4 or rung 5.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -p runs vectors
python3 gen_j2c.py vectors/crash.j2c >/dev/null
python3 gen_tiny.py vectors/tiny.pgm >/dev/null

chk 'pinned archives and fix patch' \
  '(cd pins && sha256sum -c SHA256SUMS >/dev/null 2>&1)'
chk 'pinned upstream source blobs' \
  'sha256sum -c pins/SINK_SHA256.txt >/dev/null 2>&1'
chk 'harness and vector checksums' \
  'sha256sum -c HARNESS_SHA256.txt >/dev/null 2>&1'
chk 'archived PoC is 103 bytes' '[ "$(wc -c < vectors/crash.j2c)" = 103 ]'
chk 'tiny PGM is deterministic' \
  '[ "$(sha256sum vectors/tiny.pgm | cut -d" " -f1)" = aa1ca725a7310fa2034153529e22e408de1ef4fe27adb6707d6bf04fcb9d7bca ]'
chk 'vulnerable allocation sizes one row' \
  "grep -Fq 'pre_alloc_data<ui32>(nominal.h * (size_t)stride, 0)' src-vuln/src/core/codestream/ojph_codeblock.cpp"
chk 'fixed allocation rounds to even rows' \
  "grep -Fq 'rows * (size_t)stride' src-fixed/src/core/codestream/ojph_codeblock.cpp && grep -Fq 'this->stride * ((nominal.h + 1u) & ~1u)' src-fixed/src/core/codestream/ojph_codeblock.cpp"
chk 'decoder body byte-identical across pins' \
  'cmp -s src-vuln/src/core/coding/ojph_block_decoder32.cpp src-fixed/src/core/coding/ojph_block_decoder32.cpp'

./build-vuln-plain/src/apps/ojph_compress/ojph_compress \
  -i vectors/tiny.pgm -o vectors/tiny.j2c -num_decomps 1 -reversible true \
  > runs/compress.log 2>&1
chk 'pinned compressor emits 147-byte codestream' \
  '[ "$(wc -c < vectors/tiny.j2c)" = 147 ]'
chk 'pinned codestream hash' \
  '[ "$(sha256sum vectors/tiny.j2c | cut -d" " -f1)" = 0d5774eaa5358817f88eaae24797d733a83f9224bbe810ee536a10b5464e7c2e ]'

# Full-decoder controls: no ASan fault in the library's 5%-slack slab.
for spec in 'vuln-asan tiny.j2c' 'fixed-asan tiny.j2c' 'fixed-asan crash.j2c'; do
  set -- $spec
  name="$1-$2"
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    "./build-$1/src/apps/ojph_expand/ojph_expand" -i "vectors/$2" \
    -o "runs/full-$name.pgm" > "runs/full-$name.out" 2>&1
  rc=$?
  chk "full decoder $name exits 0" "[ \"$rc\" -eq 0 ]"
  chk "full decoder $name has no ASan finding" \
    "! grep -Fq 'ERROR: AddressSanitizer' runs/full-$name.out"
done
chk 'vulnerable and fixed full decode agree on tiny codestream' \
  'cmp -s runs/full-vuln-asan-tiny.j2c.pgm runs/full-fixed-asan-tiny.j2c.pgm'

# Full-decoder reachability of the raw sink (gdb, no debugger-forced execution).
SRC="$PWD/src-vuln/src/core"
ASAN_OPTIONS=detect_leaks=0 gdb -q -batch \
  -ex 'set breakpoint pending on' \
  -ex "break $SRC/coding/ojph_block_decoder32.cpp:1155" \
  -ex 'run -i vectors/tiny.j2c -o runs/gdb-tiny.pgm' \
  "./build-vuln-asan/src/apps/ojph_expand/ojph_expand" \
  > runs/gdb-reach.out 2>&1
chk 'full decoder reaches raw sink line 1155' \
  "grep -Fq 'ojph_block_decoder32.cpp:1155' runs/gdb-reach.out"

# Direct sink on the pinned decoder: exact one-row buffer vs fixed two-row contract.
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./sink-vuln-asan 1 \
  > runs/sink-1row-asan.out 2>&1; rc=$?
chk 'one-row sink ASan faults' "[ \"$rc\" -ne 0 ]"
chk 'one-row sink ASan WRITE-4' \
  "grep -Fq 'WRITE of size 4' runs/sink-1row-asan.out"
chk 'one-row sink ASan raw sink line 1155' \
  "grep -Fq 'ojph_block_decoder32.cpp:1155' runs/sink-1row-asan.out"
chk 'one-row sink ASan zero bytes after 32-byte region' \
  "grep -Fq 'located 0 bytes after 32-byte region' runs/sink-1row-asan.out"

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./sink-vuln-asan 2 \
  > runs/sink-2row-asan.out 2>&1; rc=$?
chk 'two-row ASan control exits 0' "[ \"$rc\" -eq 0 ]"
chk 'two-row ASan control clean' \
  '! grep -Fq "ERROR: AddressSanitizer" runs/sink-2row-asan.out'
chk 'two-row ASan control writes second row' \
  'grep -Fq "ROW1_OR=b0000000" runs/sink-2row-asan.out'

./sink-vuln-plain 2 > runs/sink-2row-plain.out 2>&1; rc=$?
chk 'two-row plain control exits 0' "[ \"$rc\" -eq 0 ]"
chk 'two-row plain control writes second row' \
  'grep -Fq "ROW1_OR=b0000000" runs/sink-2row-plain.out'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
