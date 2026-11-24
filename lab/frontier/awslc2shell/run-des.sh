#!/bin/sh
# W211 replay: 8-byte-block OOB with vulnerable/fixed pinned libraries.
# Builds its own two small binaries; the libraries are built by PROVENANCE.md.
cd "$(dirname "$0")" || exit 2
pass=0
fail=0
check() {
  name=$1
  expected=$2
  actual=$3
  if [ "$expected" = "$actual" ]; then
    echo "PASS $name: $actual"
    pass=$((pass + 1))
  else
    echo "FAIL $name: expected [$expected] got [$actual]"
    fail=$((fail + 1))
  fi
}

cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I src/include \
  des-oob.c build-asan-c/crypto/libcrypto.a -lpthread -o des-vuln || exit 2
cc -fsanitize=address -fno-omit-frame-pointer -g -O0 -I src-fixed/include \
  des-oob.c build-fixed/crypto/libcrypto.a -lpthread -o des-fixed || exit 2

v_small=$(./des-vuln small 2>&1); v_small_rc=$?
v_large=$(./des-vuln large 2>&1); v_large_rc=$?
f_small=$(./des-fixed small 2>&1); f_small_rc=$?
f_large=$(./des-fixed large 2>&1); f_large_rc=$?

printf '%s\n' "$v_small" "$v_large" "$f_small" "$f_large"

check "vuln_small_asan_write_one" "1" "$(printf '%s\n' "$v_small" | grep -c 'WRITE of size 1')"
check "vuln_small_asan_via_cipher" "1" "$(printf '%s\n' "$v_small" | grep -c 'cipher.c:411')"
check "vuln_small_asan_one_past_15" "1" "$(printf '%s\n' "$v_small" | grep -c '0 bytes after 15-byte region')"
check "vuln_small_asan_des_store" "2" "$(printf '%s\n' "$v_small" | grep -c 'des.c:840')"
check "vuln_small_rc_nonzero" "yes" "$([ "$v_small_rc" -ne 0 ] && echo yes || echo no)"
check "vuln_large_clean" "1" "$(printf '%s\n' "$v_large" | grep -c 'block_size=8 cap=32 n1=0 n2=8 probe=0x48 result=OK')"
check "vuln_large_rc" "0" "$v_large_rc"
check "fixed_small_clean" "1" "$(printf '%s\n' "$f_small" | grep -c 'block_size=8 cap=15 n1=0 n2=8 probe=0xab result=OK')"
check "fixed_small_rc" "0" "$f_small_rc"
check "fixed_large_clean" "1" "$(printf '%s\n' "$f_large" | grep -c 'block_size=8 cap=32 n1=0 n2=8 probe=0xab result=OK')"
check "fixed_large_rc" "0" "$f_large_rc"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
