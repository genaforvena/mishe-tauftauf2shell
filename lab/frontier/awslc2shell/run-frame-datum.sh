#!/bin/sh
# W212 replay: one-byte CVE write corrupts a frame length; the consumer's
# second-order memcpy becomes a 72-byte heap overflow. ASan in the harness
# only; plain pinned libs. Run sh build-frame-datum.sh first.
cd "$(dirname "$0")" || exit 2
pass=0
fail=0
export ASAN_OPTIONS=detect_leaks=0

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

# Stable output only: no ASLR addresses or build paths.
run_mode() {
  bin=$1
  mode=$2
  input=$3
  if [ -n "$input" ]; then
    out=$("$bin" "$mode" < "$input" 2>&1)
  else
    out=$("$bin" "$mode" 2>&1)
  fi
  rc=$?
  printf '%s\n' "$out" | grep -oE '(^(vuln|fixed|safe|steer|wire): .*|ERROR: AddressSanitizer: heap-buffer-overflow|WRITE of size 72|SUMMARY: AddressSanitizer: heap-buffer-overflow.*in memcpy)' || true
  echo "RC $mode=$rc"
}

layout='data_off=0 len_off=31 body_off=32 struct_size=160'

./frame-datum-vuln gen 48 > /tmp/awslc-w212-ct48.bin
./frame-datum-vuln gen 02 > /tmp/awslc-w212-ct02.bin
./frame-datum-vuln gen 00 > /tmp/awslc-w212-ct00.bin

echo '--- byte-mode (ciphertext synthesised in harness) ---'
byte_vuln=$(run_mode ./frame-datum-vuln vuln)
byte_fixed=$(run_mode ./frame-datum-fixed fixed)
byte_safe=$(run_mode ./frame-datum-vuln safe)
byte_steer=$(run_mode ./frame-datum-vuln steer)
printf '%s\n%s\n%s\n%s\n' "$byte_vuln" "$byte_fixed" "$byte_safe" "$byte_steer"

echo '--- wire-mode (ciphertext from stdin) ---'
wire_vuln=$(run_mode ./frame-datum-vuln wire /tmp/awslc-w212-ct48.bin)
wire_fixed=$(run_mode ./frame-datum-fixed wire /tmp/awslc-w212-ct48.bin)
wire_steer=$(run_mode ./frame-datum-vuln wire /tmp/awslc-w212-ct02.bin)
wire_safe=$(run_mode ./frame-datum-vuln wire /tmp/awslc-w212-ct00.bin)
printf '%s\n%s\n%s\n%s\n' "$wire_vuln" "$wire_fixed" "$wire_steer" "$wire_safe"

check 'natural_layout_byte_vuln' 1 "$(printf '%s\n' "$byte_vuln" | grep -c "$layout")"
check 'natural_layout_wire_vuln' 1 "$(printf '%s\n' "$wire_vuln" | grep -c "$layout")"
check 'byte_vuln_len_corrupted' 1 "$(printf '%s\n' "$byte_vuln" | grep -c 'len_before=1 len_after=72')"
check 'byte_vuln_asan_write72' 1 "$(printf '%s\n' "$byte_vuln" | grep -c 'WRITE of size 72')"
check 'byte_vuln_abort' 'RC vuln=1' "$(printf '%s\n' "$byte_vuln" | grep '^RC ')"
check 'byte_fixed_len_clean' 1 "$(printf '%s\n' "$byte_fixed" | grep -c 'len_before=1 len_after=1')"
check 'byte_fixed_no_asan' 0 "$(printf '%s\n' "$byte_fixed" | grep -c 'AddressSanitizer')"
check 'byte_fixed_rc' 'RC fixed=0' "$(printf '%s\n' "$byte_fixed" | grep '^RC ')"
check 'byte_safe_len_clean' 1 "$(printf '%s\n' "$byte_safe" | grep -c 'len_before=0 len_after=0')"
check 'byte_safe_no_asan' 0 "$(printf '%s\n' "$byte_safe" | grep -c 'AddressSanitizer')"
check 'byte_safe_rc' 'RC safe=0' "$(printf '%s\n' "$byte_safe" | grep '^RC ')"
check 'byte_steer_len_two' 1 "$(printf '%s\n' "$byte_steer" | grep -c 'len_before=1 len_after=2')"
check 'byte_steer_no_asan' 0 "$(printf '%s\n' "$byte_steer" | grep -c 'AddressSanitizer')"
check 'byte_steer_rc' 'RC steer=0' "$(printf '%s\n' "$byte_steer" | grep '^RC ')"
check 'wire_vuln_len_corrupted' 1 "$(printf '%s\n' "$wire_vuln" | grep -c 'len_before=1 len_after=72')"
check 'wire_vuln_asan_write72' 1 "$(printf '%s\n' "$wire_vuln" | grep -c 'WRITE of size 72')"
check 'wire_vuln_abort' 'RC wire=1' "$(printf '%s\n' "$wire_vuln" | grep '^RC ')"
check 'wire_fixed_len_clean' 1 "$(printf '%s\n' "$wire_fixed" | grep -c 'len_before=1 len_after=1')"
check 'wire_fixed_no_asan' 0 "$(printf '%s\n' "$wire_fixed" | grep -c 'AddressSanitizer')"
check 'wire_fixed_rc' 'RC wire=0' "$(printf '%s\n' "$wire_fixed" | grep '^RC ')"
check 'wire_steer_len_two' 1 "$(printf '%s\n' "$wire_steer" | grep -c 'len_before=1 len_after=2')"
check 'wire_steer_no_asan' 0 "$(printf '%s\n' "$wire_steer" | grep -c 'AddressSanitizer')"
check 'wire_steer_rc' 'RC wire=0' "$(printf '%s\n' "$wire_steer" | grep '^RC ')"
check 'wire_safe_len_zero' 1 "$(printf '%s\n' "$wire_safe" | grep -c 'len_before=1 len_after=0')"
check 'wire_safe_no_asan' 0 "$(printf '%s\n' "$wire_safe" | grep -c 'AddressSanitizer')"
check 'wire_safe_rc' 'RC wire=0' "$(printf '%s\n' "$wire_safe" | grep '^RC ')"
check 'decrypt_ok_all' 8 "$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$byte_vuln" "$byte_fixed" "$byte_safe" "$byte_steer" \
  "$wire_vuln" "$wire_fixed" "$wire_steer" "$wire_safe" | grep -c 'decrypt_ok=1')"

rm -f /tmp/awslc-w212-ct48.bin /tmp/awslc-w212-ct02.bin /tmp/awslc-w212-ct00.bin
echo "RESULT: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
