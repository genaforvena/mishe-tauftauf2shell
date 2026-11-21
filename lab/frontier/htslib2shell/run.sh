#!/bin/bash
# Reproduce the pinned XPACK block_by_id OOB pointer-cache read/write.
# Usage: bash run.sh <outdir>   (fresh outdir recommended; no network)
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "${1:-$HERE/out-run}")"
mkdir -p "$OUT"
: > "$OUT/pass.log"
p(){ echo "PASS $1" | tee -a "$OUT/pass.log"; }
(cd "$HERE/src" && sha256sum -c SHA256SUMS >/dev/null)
p 'pinned SHA-256SUMS verified'
cd "$HERE"
for v in vuln plain; do
  mkdir -p "$OUT/$v"
  tar xjf src/htslib-1.23.1.tar.bz2 -C "$OUT/$v" --strip-components=1
done
mkdir -p "$OUT/fixed"
tar xjf src/htslib-1.24.tar.bz2 -C "$OUT/fixed" --strip-components=1
for v in vuln plain fixed; do
  (cd "$OUT/$v" && CFLAGS="-g -O0 $([ "$v" = vuln ] && echo '-fsanitize=address -fsanitize-recover=address')" \
    ./configure --disable-libcurl --disable-bz2 --disable-lzma >"$OUT/conf-$v.log" 2>&1 \
    && make -j4 libhts.a >"$OUT/make-$v.log" 2>&1)
done
gcc -g -O0 -fsanitize=address -fsanitize-recover=address \
  -I"$OUT/vuln" -I"$OUT/vuln/cram" -I"$OUT/vuln/htslib" \
  -o "$OUT/harness-asan" harness.c "$OUT/vuln/libhts.a" -ldeflate -lz -lpthread -lm -ldl
gcc -g -O0 -I"$OUT/plain" -I"$OUT/plain/cram" -I"$OUT/plain/htslib" \
  -o "$OUT/harness-plain" harness.c "$OUT/plain/libhts.a" -ldeflate -lz -lpthread -lm -ldl
gcc -g -O0 -fsanitize=address -I"$OUT/fixed" -I"$OUT/fixed/cram" -I"$OUT/fixed/htslib" \
  -o "$OUT/harness-fixed" harness.c "$OUT/fixed/libhts.a" -ldeflate -lz -lpthread -lm -ldl
ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 "$OUT/harness-asan" 0 >"$OUT/asan.log" 2>&1 || true
"$OUT/harness-plain" 0 >"$OUT/plain.log" 2>&1 || true
ASAN_OPTIONS=detect_leaks=0 "$OUT/harness-fixed" 0 >"$OUT/fixed.log" 2>&1 || true
grep -q 'READ of size 8' "$OUT/asan.log" && grep -q 'cram_xpack_decode_expand_char cram/cram_codecs.c:1378' "$OUT/asan.log" && p 'ASan READ of size 8 at cram_codecs.c:1378'
grep -q 'WRITE of size 8' "$OUT/asan.log" && grep -q 'cram_xpack_decode_expand_char cram/cram_codecs.c:1388' "$OUT/asan.log" && p 'ASan WRITE of size 8 at cram_codecs.c:1388'
grep -q '8 bytes after 4096-byte region' "$OUT/asan.log" && p 'OOB pointer slot 8 bytes after 4096-byte block_by_id region'
grep -q 'codec_id=1 expected=1' "$OUT/plain.log" && p 'real cram_decoder_init assigns codec_id=1'
grep -q 'cache index 512+codec_id=513 vs 512 slots' "$OUT/plain.log" && p 'OOB index 513 vs 512 allocated slots'
grep -q 'RESULT PASS' "$OUT/plain.log" && p 'unsanitized pinned library OOB read returns adjacent junk (guard early-out, no write)'
grep -q 'Unimplemented codec of type' "$OUT/fixed.log" && p 'fixed 1.24 rejects codec 51 (CRAM v4 removed)'
grep -q 'RESULT PASS' "$OUT/asan.log" && p 'harness accounting checks under ASan'
printf 'TRACE sha256=%s\n' "$(sha256sum "$OUT/pass.log" | cut -d' ' -f1)"
