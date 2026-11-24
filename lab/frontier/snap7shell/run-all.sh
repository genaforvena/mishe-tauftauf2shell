#!/bin/sh
# snap7shell W203 replay. All paths relative to this dir.
cd "$(dirname "$0")" || exit 2
pass=0
fail=0
check() {
  name=$1; expected=$2; actual=$3
  if [ "$expected" = "$actual" ]; then
    echo "PASS $name: $actual"; pass=$((pass + 1))
  else
    echo "FAIL $name: expected [$expected] got [$actual]"; fail=$((fail + 1))
  fi
}
count() { printf '%s\n' "$1" | grep -c "$2"; }

# 1. Rung 3: server-controlled DataLength drives a 65535-byte memcpy into a
#    caller-owned 1-byte heap buffer through the public ReadMultiVars API.
out=$(./vuln asan 2>&1); rc=$?
check vuln_asan_rc 1 "$rc"
check vuln_asan_write 1 "$(count "$out" 'WRITE of size 65535')"
check vuln_asan_site 1 "$(count "$out" 's7_micro_client.cpp:418')"
check vuln_asan_offset 1 "$(count "$out" '0 bytes after 1-byte region')"

# 2. Chosen bytes at chosen offsets; canary just past the declared 32 bytes.
out=$(./vuln bytes 2>&1)
check vuln_chosen_bytes 1 "$(count "$out" 'byte16=0x48 byte31=0x48 canary32=0xab')"

# 3. Safe input on the vulnerable library: no ASan report, rc 0.
out=$(./vuln safe 2>&1); rc=$?
check vuln_safe_rc 0 "$rc"
check vuln_safe_clean 0 "$(count "$out" 'ERROR: AddressSanitizer')"

# 4. Fixed control (issue #32 MaxRecv/MaxDest bounds): reject, no ASan report.
out=$(./fixed asan 2>&1); rc=$?
check fixed_reject_rc 0 "$rc"
check fixed_reject_code 1 "$(count "$out" 'rc=8388608')"
check fixed_asan_clean 0 "$(count "$out" 'ERROR: AddressSanitizer')"
out=$(./fixed bytes 2>&1)
check fixed_bytes_unchanged 1 "$(count "$out" 'byte16=0xab byte31=0xab canary32=0xab')"
out=$(./fixed safe 2>&1); rc=$?
check fixed_safe_rc 0 "$rc"

# 5. Pin integrity.
check pinned_tarball 1 "$(sha256sum snap7-30f37da.tar.gz | grep -c '^2840d50a833d928e5175b8ccc5383fae0fcc3e826c07e60b2b4190a30c613c36')"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
