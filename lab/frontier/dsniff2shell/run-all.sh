#!/bin/sh
# dsniff2shell W204 replay. All paths relative to this dir.
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

# 1. Pins: tarball and the exact vulnerable upstream source bytes.
check pinned_tarball 1 "$(sha256sum src/dsniff-2.5a2.tar.gz | grep -c '^23ada927f3d6c0229a3b624466dd9a5244018f689bbef145a030e3191610e3b4')"
check pristine_decoder 1 "$(sha256sum src/dsniff-2.5a2/decode_sniffer.c | grep -c '^b58440d541b10c69584b52ba64532288daa9e4ca5ca9ef275f304cccc5dc33b2')"
check patched_decoder 1 "$(sha256sum src/dsniff-fixed/decode_sniffer.c | grep -c '^dc7aaee927f3284ff096965192b651625e7a912f770a3a0b820df47a0c7a52dd')"

# 2. Rung 3: real upstream decoder writes past its 4096-byte output buffer.
out=$(./vuln-asan 2>&1); rc=$?
check vuln_asan_rc 1 "$rc"
check vuln_asan_global_overflow 2 "$(count "$out" 'global-buffer-overflow')"
check vuln_asan_write 1 "$(count "$out" 'WRITE of size 1')"
check vuln_asan_site 2 "$(count "$out" 'base64.c:164')"
check vuln_asan_caller 1 "$(count "$out" 'decode_sniffer.c:47')"
check vuln_asan_offset 1 "$(count "$out" "0 bytes after global variable 'obuf'")"

# 3. Chosen decoded bytes at two chosen offsets past obuf (plain build).
out=$(./vuln-plain bytes 2>&1)
check chosen_at_offset_0 1 "$(count "$out" 'guard0: 4d 49 53 48 45 2d 4f 4f')"
check chosen_at_offset_128 1 "$(count "$out" 'guard128: 4d 49 53 48 45 2d 4f 4f')"

# 4. Safe input on vulnerable decoder: no ASan report.
out=$(./vuln-asan safe 2>&1); rc=$?
check vuln_safe_rc 0 "$rc"
check vuln_safe_clean 0 "$(count "$out" 'ERROR: AddressSanitizer')"

# 5. Fixed control (clamped remaining + negative-return guard): no overflow.
out=$(./fixed-asan 2>&1); rc=$?
check fixed_attack_rc 0 "$rc"
check fixed_attack_clean 0 "$(count "$out" 'ERROR: AddressSanitizer')"
out=$(./fixed-plain bytes 2>&1)
check fixed_guard_intact 2 "$(count "$out" 'cd cd cd cd cd cd cd cd')"
out=$(./fixed-asan safe 2>&1); rc=$?
check fixed_safe_rc 0 "$rc"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
