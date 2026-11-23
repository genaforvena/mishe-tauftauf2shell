#!/bin/sh
# Deterministic assertions + normalized trace for cjose2shell.
# 8 binaries (gcc/clang x vulnerable/fixed x asan/plain) x 6 scenarios = 48
# invocations plus one gdb chosen-byte probe. Trace excludes PID, addresses
# and paths; raw outputs stay in evidence/.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() {
    if grep -qF "$2" "$1"; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing %s\n' "$3" "$2"; fi
}
expect_re() {
    if grep -Eq "$2" "$1"; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing /%s/\n' "$3" "$2"; fi
}
absent() {
    if grep -qF "$2" "$1"; then FAIL=$((FAIL+1)); printf 'FAIL %s: found %s\n' "$3" "$2";
    else PASS=$((PASS+1)); fi
}

: > "$OUT/trace.txt"
for cc in gcc clang; do
  for tree in vulnerable fixed; do
    for mode in asan plain; do
      B="$cc-$tree-$mode"
      for s in valid odd probe wrapped wrappedbig undersized; do
        F="$OUT/$B.$s.out"
        set +e
        timeout 20 "$HERE/$B" "$s" > "$F" 2>&1
        RC=$?
        set -e
        expect "$F" "SCENARIO=$s EK_LEN" "$B/$s scenario"
        expect "$F" 'IMPORT=1 ERRCODE=0' "$B/$s import"
        case "$s" in
          valid)
            expect "$F" 'DECRYPT=1 ERRCODE=0 PLAIN_LEN=15' "$B/$s decrypt"
            absent "$F" 'ERROR: AddressSanitizer' "$B/$s asan-negative"
            ;;
          odd|undersized)
            expect "$F" 'DECRYPT=0' "$B/$s decrypt-reject"
            absent "$F" 'ERROR: AddressSanitizer' "$B/$s asan-negative"
            if [ "$tree" = vulnerable ]; then
              expect "$F" 'DECRYPT=0 ERRCODE=4' "$B/$s crypto-error"
            else
              expect "$F" 'DECRYPT=0 ERRCODE=1' "$B/$s invalid-arg"
            fi
            ;;
          probe|wrapped|wrappedbig)
            if [ "$tree" = vulnerable ] && [ "$mode" = asan ]; then
              expect "$F" 'ERROR: AddressSanitizer: heap-buffer-overflow' "$B/$s asan"
              if [ "$s" = wrappedbig ]; then
                expect "$F" 'WRITE of size 1016' "$B/$s write-size"
              else
                expect "$F" 'WRITE of size 40' "$B/$s write-size"
              fi
            elif [ "$tree" = vulnerable ]; then
              if [ "$s" = wrappedbig ]; then
                expect "$F" 'free(): invalid pointer' "$B/$s heap-corruption"
                [ "$RC" -eq 134 ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf 'FAIL %s rc=%s\n' "$B/$s" "$RC"; }
              elif [ "$s" = wrapped ]; then
                expect "$F" 'CEK_LEN_AFTER=40' "$B/$s length-confusion"
                expect "$F" 'CEK_CMP_LEN=32 MISMATCHES=0' "$B/$s in-bounds-bytes"
              else
                expect "$F" 'DECRYPT=0 ERRCODE=4' "$B/$s crypto-error"
                expect "$F" 'CEK_CMP_LEN=32 MISMATCHES=0' "$B/$s in-bounds-bytes"
              fi
            else
              expect "$F" 'DECRYPT=0 ERRCODE=1' "$B/$s invalid-arg"
              expect "$F" 'CEK_LEN_AFTER=32' "$B/$s cek-unchanged"
              absent "$F" 'ERROR: AddressSanitizer' "$B/$s asan-negative"
            fi
            ;;
        esac
        printf '%s %s rc=%s\n' "$B" "$s" "$RC" >> "$OUT/trace.txt"
      done
    done
  done
done

# Rung 4: chosen bytes at cek+32..39, observed at the real library unwrap call.
G="$OUT/gdb-chosen.out"
gdb -q -batch \
  -ex 'break AES_unwrap_key' \
  -ex 'ignore 1 1' \
  -ex 'run wrapped' \
  -ex 'printf "LIB_UNWRAP_INLEN=%lu OUTPTR=%p\n", $r8, $rdx' \
  -ex 'set $out=$rdx' \
  -ex 'finish' \
  -ex 'x/48xb $out' \
  "$HERE/gcc-vulnerable-plain" > "$G" 2>&1
expect "$G" 'LIB_UNWRAP_INLEN=48' 'gdb-inlen'
expect_re "$G" '0x4d.*0x49.*0x53.*0x48.*0x45.*0x2d.*0x4f.*0x4f' 'gdb-chosen-bytes'
expect "$G" 'jwe.c:595' 'gdb-library-frame'

HASH=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d trace=%s\n' "$PASS" "$FAIL" "$HASH" > "$OUT/summary.txt"
cat "$OUT/summary.txt"
[ "$FAIL" -eq 0 ]
