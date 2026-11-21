#!/usr/bin/env bash
# Consumer-reality check for OSV-2025-219 on this host's glibc 2.39.
# Does the real, unsanitized, verbatim-pinned opj_decompress consume the OOB
# write, and does it land on a live neighbour? All local process only.
# Requires the pinned builds produced by `bash run.sh <dir>` first.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out-consumer"}
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd) || exit 2
cd "$HERE" || exit 2
V=$HERE/out-w75/build/vuln-plain/bin/opj_decompress
F=$HERE/out-w75/build/fixed-plain/bin/opj_decompress
if [ ! -x "$V" ] || [ ! -x "$F" ]; then
  echo "missing pinned builds: run 'bash run.sh $HERE/out-w75' first" >&2
  exit 2
fi
: > "$OUT/results.tmp"
pass=0; fail=0
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
check() {
  if [ "$2" = 1 ]; then echo "PASS $1" | tee -a "$OUT/results.tmp"; pass=$((pass+1))
  else echo "FAIL $1" | tee -a "$OUT/results.tmp"; fail=$((fail+1)); fi
}

"$V" -i "$HERE/src/poc.j2k" -o "$OUT/orig.tif" > "$OUT/orig.log" 2>&1
orc=$?; ol=$(cat "$OUT/orig.log")
check "pinned unsanitized decoder aborts on public PoC (rc=134, munmap_chunk)" \
  "$([ "$orc" = 134 ] && contains 'munmap_chunk(): invalid pointer' "$ol" && echo 1 || echo 0)"

"$V" -i "$HERE/poc-pad.j2k" -o "$OUT/pad.tif" > "$OUT/pad.log" 2>&1
prc=$?; pl=$(cat "$OUT/pad.log")
check "pinned unsanitized decoder aborts on padded PoC (rc=134, munmap_chunk)" \
  "$([ "$prc" = 134 ] && contains 'munmap_chunk(): invalid pointer' "$pl" && echo 1 || echo 0)"

"$F" -i "$HERE/poc-pad.j2k" -o "$OUT/fixed.tif" > "$OUT/fixed.log" 2>&1
frc=$?; fl=$(cat "$OUT/fixed.log")
check "fixed pin 91d08b11 decodes padded PoC cleanly (rc=0, no abort)" \
  "$([ "$frc" = 0 ] && ! contains 'Sanitizer' "$fl" && \
    ! contains 'munmap_chunk' "$fl" && ! contains 'invalid pointer' "$fl" && \
    contains 'Generated Outfile' "$fl" && echo 1 || echo 0)"

python3 -c 'd=bytearray(open("'"$HERE"'/src/poc.j2k","rb").read()); assert d[155]==1; d[155]=0; open("'"$OUT"'/poc-tpsot0.j2k","wb").write(d)' || exit 2
"$V" -i "$OUT/poc-tpsot0.j2k" -o "$OUT/tpsot0.tif" > "$OUT/tpsot0.log" 2>&1
crc=$?; cl=$(cat "$OUT/tpsot0.log")
check "TPsot=0 control removes the OOB and the allocator abort" \
  "$([ "$crc" = 1 ] && ! contains 'munmap_chunk' "$cl" && \
    contains 'Invalid tile part index' "$cl" && echo 1 || echo 0)"

gdb -q -batch -ex "set args -i $HERE/poc-pad.j2k -o $OUT/gdb-out.tif" -x "$HERE/consumer-reality.gdb" "$V" > "$OUT/gdb-live.log" 2>&1
mapfile -t H < <(grep '^H ' "$OUT/gdb-live.log")
if [ "${#H[@]}" -lt 3 ]; then echo "FAIL gdb sink hits observed" | tee -a "$OUT/results.tmp"; echo "RESULT $pass PASS / $((fail+1)) FAIL"; exit 1; fi
check "gdb observes the three real sink hits on tile 0 then tile 1" \
  "$([ "${#H[@]}" = 3 ] && contains 'tile=0 tpsno=1' "${H[0]}" && \
    contains 'tile=0 tpsno=2' "${H[1]}" && contains 'tile=1 tpsno=0' "${H[2]}" && echo 1 || echo 0)"

get() { local s=${1#*"$2="}; echo "${s%% *}"; }
p2=$(get "${H[0]}" pos); p3=$(get "${H[1]}" pos)
b0=$(get "${H[0]}" base0); b1=$(get "${H[2]}" base1)
oob2=$(get "${H[1]}" oob1)
sz2=$(get "${H[1]}" size56); sz3=$(get "${H[2]}" size56)
check "live tile 1 tp_index array begins 32 bytes after tile 0 (the OOB target)" \
  "$(( b1 == b0 + 32 ))"
check "Tpsot=1 store's chosen offset appears in tile 1 live tp_index.start_pos" \
  "$(( oob2 == p2 ))"
check "Tpsot=2 store's chosen offset overwrites that live chunk's size word" \
  "$(( sz3 == p3 ))"
check "corrupted size word sets IS_MMAPPED (explains munmap_chunk abort)" \
  "$(( (sz3 & 2) != 0 ))"
check "same size word was intact before the stores (PREV_INUSE only)" \
  "$(( (sz2 & 7) == 1 ))"

trace=$(grep '^PASS ' "$OUT/results.tmp" | sha256sum | cut -d' ' -f1)
echo "TRACE $trace"
echo "RESULT $pass PASS / $fail FAIL"
[ "$fail" = 0 ]
