#!/bin/sh
# W208 replay: natural-layout global record; the CVE byte hits adjacent state.
# Run sh build-global-datum.sh first; this script does not rebuild the libraries.
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

vuln=$(./global-datum-vuln vuln 2>&1); vuln_rc=$?
fixed=$(./global-datum-fixed fixed 2>&1); fixed_rc=$?
safe=$(./global-datum-vuln safe 2>&1); safe_rc=$?
steer=$(./global-datum-vuln steer 2>&1); steer_rc=$?

printf '%s\n%s\n%s\n%s\n' "$vuln" "$fixed" "$safe" "$steer"

check "natural_layout" "1" "$(printf '%s\n' "$vuln" | grep -c 'buf_off=0 state_off=31 handler_off=32 struct_size=40')"
check "vuln_state_hit" "1" "$(printf '%s\n' "$vuln" | grep -c 'chosen=0x48 state_before=0xa5 state_after=0x48')"
check "vuln_rc" "0" "$vuln_rc"
check "fixed_state_clean" "1" "$(printf '%s\n' "$fixed" | grep -c 'chosen=0x48 state_before=0xa5 state_after=0xa5')"
check "fixed_rc" "0" "$fixed_rc"
check "safe_state_clean" "1" "$(printf '%s\n' "$safe" | grep -c 'chosen=0x00 state_before=0x00 state_after=0x00')"
check "safe_rc" "0" "$safe_rc"
check "steer_state_hit" "1" "$(printf '%s\n' "$steer" | grep -c 'chosen=0x01 state_before=0xa5 state_after=0x01')"
check "steer_rc" "0" "$steer_rc"
check "handler_lsb_same_vuln" "1" "$(printf '%s\n' "$vuln" | grep -c 'handler_lsb_before=\(....\) handler_lsb_after=\1')"
check "handler_lsb_same_fixed" "1" "$(printf '%s\n' "$fixed" | grep -c 'handler_lsb_before=\(....\) handler_lsb_after=\1')"
check "handler_lsb_same_safe" "1" "$(printf '%s\n' "$safe" | grep -c 'handler_lsb_before=\(....\) handler_lsb_after=\1')"
check "handler_lsb_same_steer" "1" "$(printf '%s\n' "$steer" | grep -c 'handler_lsb_before=\(....\) handler_lsb_after=\1')"
check "vuln_decrypt_ok" "1" "$(printf '%s\n' "$vuln" | grep -c 'decrypt_ok=1')"
check "fixed_decrypt_ok" "1" "$(printf '%s\n' "$fixed" | grep -c 'decrypt_ok=1')"

echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
