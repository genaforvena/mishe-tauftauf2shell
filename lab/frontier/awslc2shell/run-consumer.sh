#!/bin/sh
# Loopback consumer replay for CVE-2026-134056: chosen byte redirects an
# adjacent dispatch pointer in the vulnerable build; controls stay normal.
# All paths relative to this directory. No external network access.
cd "$(dirname "$0")" || exit 2
if [ ! -x ./consumer-vuln ] || [ ! -x ./consumer-fixed ]; then
  sh build-consumer.sh || exit 2
fi
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

vuln=$(./consumer-vuln vuln 2>&1)
check "vuln_redirect_low_byte" "1" "$(printf '%s\n' "$vuln" | grep -c 'handler_after=.*low=0x48')"
check "vuln_benign_marker" "1" "$(printf '%s\n' "$vuln" | grep -c 'BENIGN_MARKER_EXECUTED')"
check "vuln_no_asan_report" "0" "$(printf '%s\n' "$vuln" | grep -c 'ERROR: AddressSanitizer')"

fixed=$(./consumer-fixed vuln 2>&1)
check "fixed_pointer_intact" "1" "$(printf '%s\n' "$fixed" | grep -c 'handler_after=.*low=0x00')"
check "fixed_normal_handler" "1" "$(printf '%s\n' "$fixed" | grep -c 'NORMAL_HANDLER')"

safe=$(./consumer-vuln safe 2>&1)
check "safe_pointer_intact" "1" "$(printf '%s\n' "$safe" | grep -c 'handler_after=.*low=0x00')"
check "safe_normal_handler" "1" "$(printf '%s\n' "$safe" | grep -c 'NORMAL_HANDLER')"

nopad=$(./consumer-vuln nopad 2>&1)
check "nopad_pointer_intact" "1" "$(printf '%s\n' "$nopad" | grep -c 'handler_after=.*low=0x00')"
check "nopad_normal_handler" "1" "$(printf '%s\n' "$nopad" | grep -c 'NORMAL_HANDLER')"

single=$(./consumer-vuln single 2>&1)
check "single_no_adjacent_pointer" "1" "$(printf '%s\n' "$single" | grep -c 'single_call_no_adjacent_pointer')"

other=$(./consumer-vuln vuln 00 2>&1)
check "safe_input_byte_normal" "1" "$(printf '%s\n' "$other" | grep -c 'NORMAL_HANDLER')"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
