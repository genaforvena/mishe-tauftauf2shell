#!/bin/sh
# AWS-LC CVE-2026-134056 frontier lab replay. All paths relative to this dir.
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

# 1. ASan-instrumented C AES path: the actual out-of-bounds WRITE is caught.
out=$(./harness-c asan 2>&1)
rc=$?
check "vuln_asan_rc" "1" "$rc"
check "vuln_asan_write" "1" "$(printf '%s\n' "$out" | grep -c 'WRITE of size 16')"
check "vuln_asan_site" "1" "$(printf '%s\n' "$out" | grep -c 'cipher.c:411')"
check "vuln_asan_offset" "1" "$(printf '%s\n' "$out" | grep -c '0 bytes after 31-byte region')"

# 2. Default assembly AES path: ASan sees the subsequent OOB read of the
#    withheld-block copy, because assembly stores are not instrumented.
out=$(./harness-vuln asan 2>&1)
check "vuln_asm_asan_read" "1" "$(printf '%s\n' "$out" | grep -c 'READ of size 16 at')"
check "vuln_asm_asan_site" "1" "$(printf '%s\n' "$out" | grep -c 'cipher.c:420')"

# 3. Chosen byte: stop after two updates, one extra allocated byte; the OOB
#    byte at offset 31 changes from canary 0xab to the chosen 'H' (0x48).
out=$(./harness-vuln byte2 2>&1)
check "vuln_chosen_byte" "1" "$(printf '%s\n' "$out" | grep -c 'byte31=0x48 chosen=0x48 CHOSEN_BYTE_PRESENT')"
out=$(./harness-fixed byte2 2>&1)
check "fixed_byte_unmodified" "1" "$(printf '%s\n' "$out" | grep -c 'byte31=0xab chosen=0x48 CHOSEN_BYTE_ABSENT')"

# 4. Fixed control: exact documented-minimum buffer, no ASan report.
out=$(./harness-fixed asan 2>&1)
rc=$?
check "fixed_asan_rc" "0" "$rc"
check "fixed_asan_clean" "0" "$(printf '%s\n' "$out" | grep -c 'ERROR: AddressSanitizer')"

# 5. Safe-input controls on the vulnerable library.
out=$(./harness-vuln single 2>&1)
check "vuln_single_clean" "0" "$(printf '%s\n' "$out" | grep -c 'ERROR: AddressSanitizer')"
out=$(./harness-vuln nopad 2>&1)
check "vuln_nopad_clean" "0" "$(printf '%s\n' "$out" | grep -c 'ERROR: AddressSanitizer')"

# 6. Pin integrity.
check "vuln_cipher_sha" "1" "$(sha256sum src/crypto/fipsmodule/cipher/cipher.c | grep -c '^72797ecccdd9fc8572962f00a7aba609a183eb1cf3dfd5e7b9a199d51f6250cb')"
check "fixed_cipher_sha" "1" "$(sha256sum src-fixed/crypto/fipsmodule/cipher/cipher.c | grep -c '^b40e79909b53a7e0eb6533e73ac328d099699fa4ea26fc18a859c6000b2754e7')"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
