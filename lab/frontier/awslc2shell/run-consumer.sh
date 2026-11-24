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


# Natural-alignment modes: compiler-chosen layout, no aligned dispatch table
# and no indirect call. Compare before/after handler LSBs per binary because
# each build's handler address has its own fixed low byte.
before_lsb() {
  printf '%s\n' "$1" | sed -n 's/.*handler_before=.*low=0x\([0-9a-f][0-9a-f]\).*/\1/p'
}
after_lsb() {
  printf '%s\n' "$1" | sed -n 's/.*handler_after=.*low=0x\([0-9a-f][0-9a-f]\).*/\1/p'
}

nat_tag_v=$(./consumer-vuln natural_tag 2>&1)
v=$(before_lsb "$nat_tag_v")
w=$(after_lsb "$nat_tag_v")
check "natural_tag_vuln_lsb_is_chosen" "48" "$w"
check "natural_tag_vuln_lsb_changed" "1" "$([ "$w" != "$v" ] && echo 1 || echo 0)"
check "natural_tag_vuln_layout" "1" "$(printf '%s\n' "$nat_tag_v" | grep -c 'mode=natural_tag layout scratch_off=1 handler_off=32 oob_byte=0x48')"
check "natural_tag_vuln_no_indirect_call" "1" "$(printf '%s\n' "$nat_tag_v" | grep -c 'mode=natural_tag natural_layout_no_indirect_call')"
check "natural_tag_vuln_no_asan_report" "0" "$(printf '%s\n' "$nat_tag_v" | grep -c 'ERROR: AddressSanitizer')"

nat_tag_f=$(./consumer-fixed natural_tag 2>&1)
v=$(before_lsb "$nat_tag_f")
w=$(after_lsb "$nat_tag_f")
check "natural_tag_fixed_lsb_unchanged" "$v" "$w"
# Here byte 31 is the pointer LSB itself, initialized to the handler address.
check "natural_tag_fixed_pointer_bytes_intact" "1" "$(printf '%s\n' "$nat_tag_f" | grep -c "mode=natural_tag layout scratch_off=1 handler_off=32 oob_byte=0x$v")"

nat_pad_v=$(./consumer-vuln natural_pad 2>&1)
v=$(before_lsb "$nat_pad_v")
w=$(after_lsb "$nat_pad_v")
check "natural_pad_vuln_lsb_unchanged" "$v" "$w"
check "natural_pad_vuln_byte31_chosen" "1" "$(printf '%s\n' "$nat_pad_v" | grep -c 'mode=natural_pad layout scratch_off=0 handler_off=32 oob_byte=0x48')"
check "natural_pad_vuln_no_asan_report" "0" "$(printf '%s\n' "$nat_pad_v" | grep -c 'ERROR: AddressSanitizer')"

nat_pad_f=$(./consumer-fixed natural_pad 2>&1)
v=$(before_lsb "$nat_pad_f")
w=$(after_lsb "$nat_pad_f")
check "natural_pad_fixed_lsb_unchanged" "$v" "$w"
check "natural_pad_fixed_byte31_canary" "1" "$(printf '%s\n' "$nat_pad_f" | grep -c 'mode=natural_pad layout scratch_off=0 handler_off=32 oob_byte=0xab')"
echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
