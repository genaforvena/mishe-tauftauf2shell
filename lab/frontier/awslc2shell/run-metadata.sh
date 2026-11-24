#!/bin/sh
# W206 replay: plain-process allocator-metadata negative for CVE-2026-134056.
# Run sh build-plain.sh first; this script does not rebuild the libraries.
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

vuln=$(./metadata-vuln vuln 2>&1)
vuln_rc=$?
fixed=$(./metadata-fixed fixed 2>&1)
fixed_rc=$?

printf '%s\n%s\n' "$vuln" "$fixed"

check "vuln_chosen_byte" "1" "$(printf '%s\n' "$vuln" | grep -c 'byte31=0x48 chosen=0x48')"
check "fixed_byte_unchanged" "1" "$(printf '%s\n' "$fixed" | grep -c 'byte31=0xab chosen=0x48')"
check "vuln_rc" "0" "$vuln_rc"
check "fixed_rc" "1" "$fixed_rc"
check "vuln_metadata_unchanged" "1" "$(printf '%s\n' "$vuln" | grep -c 'header_unchanged=1')"
check "fixed_metadata_unchanged" "1" "$(printf '%s\n' "$fixed" | grep -c 'header_unchanged=1')"
check "vuln_neighbor_unchanged" "1" "$(printf '%s\n' "$vuln" | grep -c 'neighbor_unchanged=1')"
check "fixed_neighbor_unchanged" "1" "$(printf '%s\n' "$fixed" | grep -c 'neighbor_unchanged=1')"
check "vuln_decrypt_ok" "1" "$(printf '%s\n' "$vuln" | grep -c 'decrypt_ok=1')"
check "fixed_decrypt_ok" "1" "$(printf '%s\n' "$fixed" | grep -c 'decrypt_ok=1')"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
