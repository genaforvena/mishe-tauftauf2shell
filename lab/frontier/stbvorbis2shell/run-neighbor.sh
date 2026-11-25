#!/bin/sh
# W205: does the 30-word OOB run cross any *live* glibc allocation, with no
# planted victim and no forced allocator layout? The pinned source gets a
# 3-line hook in setup_malloc() that calls w205_watch8() on every 8-byte
# allocation; the harness records live allocations via malloc/free wrappers.
# The 4th 8-byte allocation in this PoC is c->multiplicands (count8=4). Fixed
# dev branch and safe input are controls. No wrapped pointer is called.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/neighbor/vuln build/neighbor/fixed
cp harness-neighbor.c build/neighbor/vuln/
cp harness-neighbor-fixed.c build/neighbor/fixed/
cp pinned/stb_vorbis-dev.c build/neighbor/fixed/stb_vorbis.c
python3 - <<'PY'
from pathlib import Path
for flavor, name in (('vuln', 'stb_vorbis.c'),):
    text = (Path('pinned') / name).read_text()
    needle = '   return sz ? malloc(sz) : NULL;\n'
    assert text.count(needle) == 1, (name, text.count(needle))
    replacement = '''   if (sz == 8) {
      extern void w205_watch8(void *, size_t);
      void *w = sz ? malloc(sz) : NULL;
      w205_watch8(w, 8);
      return w;
   }
   return sz ? malloc(sz) : NULL;
'''
    (Path('build/neighbor') / flavor / 'stb_vorbis.c').write_text(
        text.replace(needle, replacement))
PY
gcc -g -O0 -o build/neighbor/vuln/harness-neighbor build/neighbor/vuln/harness-neighbor.c -lm || exit 2
gcc -g -O0 -o build/neighbor/fixed/harness-neighbor-fixed build/neighbor/fixed/harness-neighbor-fixed.c -lm || exit 2
python3 gen_poc.py evidence/chosen.ogg 16519105 65 0x4b434148 >/dev/null || exit 2
./build/neighbor/vuln/harness-neighbor evidence/chosen.ogg > evidence/neighbor-vuln-attack.out 2>&1
VULN_RC=$?
./build/neighbor/fixed/harness-neighbor-fixed evidence/chosen.ogg > evidence/neighbor-fixed-attack.out 2>&1
FIXED_RC=$?
./build/neighbor/vuln/harness-neighbor evidence/safe-input.bin > evidence/neighbor-vuln-safe.out 2>&1
SAFE_RC=$?
PASS=0; FAIL=0
check() {
  if grep -qF "$2" "$3"; then
    PASS=$((PASS+1)); echo "PASS $1 $2"
  else
    FAIL=$((FAIL+1)); echo "FAIL $1 expected $2"
  fi
}
[ "$VULN_RC" -eq 0 ] && { PASS=$((PASS+1)); echo "PASS vuln_rc rc=0"; } || { FAIL=$((FAIL+1)); echo "FAIL vuln_rc rc=$VULN_RC"; }
[ "$FIXED_RC" -eq 0 ] && { PASS=$((PASS+1)); echo "PASS fixed_rc rc=0"; } || { FAIL=$((FAIL+1)); echo "FAIL fixed_rc rc=$FIXED_RC"; }
[ "$SAFE_RC" -eq 0 ] && { PASS=$((PASS+1)); echo "PASS safe_rc rc=0"; } || { FAIL=$((FAIL+1)); echo "FAIL safe_rc rc=$SAFE_RC"; }
check vuln_snapshot 'watch=' evidence/neighbor-vuln-attack.out
check vuln_source_stop 'err=20' evidence/neighbor-vuln-attack.out
check fixed_rejects 'err=20' evidence/neighbor-fixed-attack.out
check safe_rejects 'err=30' evidence/neighbor-vuln-safe.out
if grep -q '^overlap ' evidence/neighbor-vuln-attack.out; then
  FAIL=$((FAIL+1)); echo "FAIL no_live_overlap unexpected overlap line"
else
  PASS=$((PASS+1)); echo "PASS no_live_overlap zero live allocations in [+8,+128)"
fi
if grep -q '^live seq=' evidence/neighbor-vuln-attack.out; then
  PASS=$((PASS+1)); echo "PASS live_dump recorded live allocations"
else
  FAIL=$((FAIL+1)); echo "FAIL live_dump no allocation records"
fi
echo "TOTAL PASS=$PASS FAIL=$FAIL"
cat evidence/neighbor-vuln-attack.out
[ "$FAIL" -eq 0 ]
