#!/usr/bin/env bash
# nfdump2shell staged proof runner. All binaries are local; no network use.
set -u
cd "$(dirname "$0")"
H=harness
mkdir -p "$H/out"
CFLAGS="-O0 -g -fno-omit-frame-pointer -I$H -I$H/../pins"
PASS=0; FAIL=0
ok()   { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }

gcc  $CFLAGS -DVULN=1 -fsanitize=address -o "$H/out/vuln-asan"   "$H/driver.c" || exit 2
gcc  $CFLAGS -DVULN=0 -fsanitize=address -o "$H/out/fixed-asan"  "$H/driver.c" || exit 2
gcc  $CFLAGS -DVULN=1 -o "$H/out/vuln-plain"  "$H/driver.c" || exit 2
gcc  $CFLAGS -DVULN=0 -o "$H/out/fixed-plain" "$H/driver.c" || exit 2
if command -v clang >/dev/null 2>&1; then
  clang $CFLAGS -DVULN=1 -fsanitize=address -o "$H/out/vuln-clang-asan" "$H/driver.c" || exit 2
fi

# Rung 3: ASan-confirmed heap OOB write of size 8, 0 bytes past the exact allocation.
ASAN=$("$H/out/vuln-asan" attack 2>&1); RC=$?
printf '%s\n' "$ASAN" > "$H/out/vuln-asan-attack.log"
case "$ASAN" in
  *"heap-buffer-overflow"*"WRITE of size 8"*"0 bytes after"*) ok "gcc-asan attack WRITE-8 exact allocation";;
  *) bad "gcc-asan attack WRITE-8 exact allocation (rc=$RC)";;
esac
case "$ASAN" in
  *"Process_nfd"*|*"process-parent.inc"*) ok "gcc-asan stack reaches pinned Process_nfd";;
  *) bad "gcc-asan stack reaches pinned Process_nfd";;
esac
if [ -x "$H/out/vuln-clang-asan" ]; then
  CL=$("$H/out/vuln-clang-asan" attack 2>&1)
  printf '%s\n' "$CL" > "$H/out/vuln-clang-asan-attack.log"
  case "$CL" in
    *"heap-buffer-overflow"*"WRITE of size 8"*) ok "clang-asan attack WRITE-8";;
    *) bad "clang-asan attack WRITE-8";;
  esac
fi

# Fixed commit and safe inputs stay clean.
FX=$("$H/out/fixed-asan" attack 2>&1); RC=$?
case "$FX" in
  *AddressSanitizer*) bad "fixed-asan attack must be clean";;
  *"Corrupt nfd record"*|*"too short"*) [ "$RC" -eq 0 ] && ok "fixed-asan rejects short EXgenericFlow (VerifyV3Record)" || bad "fixed-asan rc=$RC";;
  *) bad "fixed-asan did not report short extension";;
esac
for BIN in vuln-asan fixed-asan; do
  for MODE in safe-full safe-empty; do
    O=$("$H/out/$BIN" "$MODE" 2>&1); RC=$?
    case "$O" in
      *AddressSanitizer*) bad "$BIN $MODE ASan";;
      *) [ "$RC" -eq 0 ] && ok "$BIN $MODE clean" || bad "$BIN $MODE rc=$RC";;
    esac
  done
done

# Rung 4 PARTIAL: plain build, trailing canary region observes the chosen
# 64-bit msecReceived value written 0..8 bytes past the declared element.
PL=$("$H/out/vuln-plain" attack canary 2>&1); RC=$?
printf '%s\n' "$PL" > "$H/out/vuln-plain-attack-canary.log"
EXPECT=$(printf '%s\n' "$PL" | sed -n 's/^EXPECTED_BYTES=//p')
AFTER=$(printf '%s\n' "$PL"  | sed -n 's/^CANARY_AFTER=//p')
if [ "$RC" -eq 0 ] && [ -n "$EXPECT" ] && [ "$AFTER" = "$EXPECT" ]; then
  ok "plain chosen value $AFTER at element end"
else
  bad "plain chosen value (rc=$RC expect=$EXPECT after=$AFTER)"
fi
FP=$("$H/out/fixed-plain" attack canary 2>&1); RC=$?
FAFTER=$(printf '%s\n' "$FP" | sed -n 's/^CANARY_AFTER=//p')
if [ "$RC" -eq 0 ] && [ "$FAFTER" = "5a5a5a5a5a5a5a5a" ]; then
  ok "fixed plain leaves canary untouched"
else
  bad "fixed plain canary (rc=$RC after=$FAFTER)"
fi

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
