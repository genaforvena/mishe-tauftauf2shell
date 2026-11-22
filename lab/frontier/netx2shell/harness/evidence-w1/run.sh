#!/bin/bash
# Reproduce wake W1's chosen-byte readback on the plain and ASan builds.
# All inputs are local; no network. Run from this directory.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
H=$(cd "$HERE/.." && pwd)
cd "$H"

run_dump() {  # $1 = binary, $2 = input subdir, $3 = output log
  gdb -q -batch \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex 'break netx_oversized.c:65' -ex 'run manual' \
    -ex "restore $HERE/${2}/mod.bin binary &manual_modulus" \
    -ex "restore $HERE/${2}/sig.bin binary &signature_data" \
    -ex "restore $HERE/${2}/exp.bin binary &exponent" \
    -ex 'set $buf = (unsigned char*)&decrypted_signature' \
    -ex 'break _nx_crypto_rsa_operation' -ex 'continue' \
    -ex 'printf "=== BEFORE ===\n"' -ex 'x/1024bx $buf' \
    -ex 'break netx_oversized.c:104' -ex 'continue' \
    -ex 'printf "=== AFTER ===\n"' -ex 'x/1024bx $buf' \
    "./$1" > "$HERE/$3" 2>&1
}

python3 "$HERE/gen-crafted.py"
bash "$H/build-plain.sh"
run_dump netx_vuln_plain  .  vuln-crafted-A-bss.txt
run_dump netx_vuln_plain  b  vuln-crafted-B-bss.txt
run_dump netx_fixed_plain .  fixed-crafted-A-bss.txt

# Same crafted inputs under the existing ASan build: expect the same fault frame.
gdb -q -batch \
  -ex 'set pagination off' -ex 'set confirm off' \
  -ex 'break netx_oversized.c:65' -ex 'run manual' \
  -ex "restore $HERE/mod.bin binary &manual_modulus" \
  -ex "restore $HERE/sig.bin binary &signature_data" \
  -ex "restore $HERE/exp.bin binary &exponent" \
  -ex 'continue' \
  ./netx_vuln > "$HERE/vuln-crafted-A-asan.txt" 2>&1 || true
grep -E 'AddressSanitizer|WRITE of size|SUMMARY' "$HERE/vuln-crafted-A-asan.txt" | head -5
echo "logs in $HERE"
