#!/bin/sh
# W204: file-chosen words cross into a live adjacent object with a pointer
# field. The pinned source is verbatim; only malloc/free are wrapped. The
# wrapped pointer is never called. Fixed and safe inputs are controls.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/object/vuln build/object/fixed
cp harness-object.c build/object/vuln/
cp harness-object.c build/object/fixed/
cp pinned/stb_vorbis.c build/object/vuln/stb_vorbis.c
cp pinned/stb_vorbis-dev.c build/object/fixed/stb_vorbis.c
gcc -g -O0 -o build/object/vuln/harness-object build/object/vuln/harness-object.c -lm || exit 2
gcc -g -O0 -o build/object/fixed/harness-object build/object/fixed/harness-object.c -lm || exit 2
python3 gen_poc.py evidence/chosen.ogg 16519105 65 0x4b434148 >/dev/null || exit 2
printf 'not an ogg file\n' > evidence/safe-input.bin
./build/object/vuln/harness-object evidence/chosen.ogg > evidence/object-vuln-attack.out 2>&1
VULN_RC=$?
./build/object/fixed/harness-object evidence/chosen.ogg > evidence/object-fixed-attack.out 2>&1
FIXED_RC=$?
./build/object/vuln/harness-object evidence/safe-input.bin > evidence/object-vuln-safe.out 2>&1
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
check vuln_stop_err 'open_memory=(nil) err=20' evidence/object-vuln-attack.out
check vuln_adjacent_object 'victim[4] changed=120 sizeof=136' evidence/object-vuln-attack.out
check vuln_chosen_fp_low 'fp_low=0x4b434148' evidence/object-vuln-attack.out
check other_victims_untouched 'victim[3] changed=0 sizeof=136' evidence/object-vuln-attack.out
check fixed_rejects 'open_memory=(nil) err=20 bytes=205 guarded=0' evidence/object-fixed-attack.out
check safe_rejects 'open_memory=(nil) err=30 bytes=16 guarded=0' evidence/object-vuln-safe.out
echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
