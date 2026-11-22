#!/bin/bash
# Build verbatim pinned-function harnesses and replay the ntpsec2shell cases.
# No sockets are opened; all work is local to this process and its heap.
set -u
cd "$(dirname "$0")" || exit 1
H=$PWD; R=$H/../pins; E=$H/../evidence
mkdir -p "$E"
CC=${CC:-gcc}
CFLAGS="-O0 -g -std=gnu99 -I$H -I$R -Wno-unused-variable"
ASAN="-fsanitize=address -fno-omit-frame-pointer"
pass=0; fail=0
check() {
  local name=$1 ok=$2 detail=$3
  if [ "$ok" = 1 ]; then printf 'PASS %s %s\n' "$name" "$detail"; pass=$((pass+1));
  else printf 'FAIL %s %s\n' "$name" "$detail"; fail=$((fail+1)); fi
}
# Assert substrings and an exact return code; ok=1 means all held.
assert_case() {
  local name=$1 out=$2 want_rc=$3; shift 3
  local ok=1 pat
  for pat in "$@"; do printf '%s\n' "$out" | grep -qF "$pat" || ok=0; done
  [ "$rc" -eq "$want_rc" ] || ok=0
  check "$name" "$ok" "rc=$rc"
}
$CC $CFLAGS -DAES_SIV_Decrypt=libaes_siv_Decrypt -c "$R/aes_siv.c" -o "$H/aes_siv_obj.o" || exit 1
build() {
  local pin=$1 bin=$2 flags=$3
  python3 "$H/gen.py" "$pin" >/dev/null || return 1
  $CC $CFLAGS $flags -o "$bin" "$H/harness.c" "$H/aes_siv_obj.o" -lcrypto || return 1
}
for pin in vuln fixed; do
  build "$pin" "$H/s-$pin-asan" "$ASAN" || exit 1
  build "$pin" "$H/s-$pin-plain" "-DSLACK" || exit 1
  python3 "$H/gen.py" "$pin" >/dev/null || exit 1
  $CC $CFLAGS $ASAN -DREAL_CRYPTO -o "$H/r-$pin" "$H/harness.c" "$H/aes_siv_obj.o" -lcrypto || exit 1
done
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_summary=1
# 1. ASan: modeled consumer writes 40 bytes 8 bytes past an exact 128-byte packet.
o=$($H/s-vuln-asan stub-vuln-n64-41 2>&1); rc=$?
assert_case stub-asan-vuln-write "$o" 1 \
  'ERROR: AddressSanitizer: heap-buffer-overflow' 'WRITE of size 40' \
  '8 bytes after 128-byte region' 'in extens_client_recv'
printf '%s\n' "$o" > "$E/stub-asan-vuln.txt"
# 2. Fixed pin rejects before the consumer.
o=$($H/s-fixed-asan stub-fixed-n64-41 2>&1); rc=$?
assert_case fixed-rejects-n64 "$o" 1 \
  'CASE=stub-fixed-n64-41 FN_RC=0 WRITE_OFF=-1 WRITE_LEN=0'
printf '%s\n' "$o" > "$E/stub-asan-fixed.txt"
# 3/4. Modeled chosen bytes in padded plain builds; the pad is only there to
# keep glibc metadata intact for readback after the modeled OOB write.
sixteen41=$(printf '41%.0s' $(seq 1 16)); sixteen5a=$(printf '5a%.0s' $(seq 1 16))
for spec in "41:$sixteen41" "5a:$sixteen5a"; do
  f=${spec%%:*}; want=${spec##*:}
  o=$($H/s-vuln-plain "stub-vuln-n64-$f" 2>&1); rc=$?
  assert_case "chosen-$f" "$o" 1 \
    "WRITE_OFF=136 WRITE_LEN=40 BYTES=$want" "CASE=stub-vuln-n64-$f"
  printf '%s\n' "$o" > "$E/stub-plain-$f.txt"
done
# 5/6. Safe noncelen=16 stays inside the declared packet on both pins.
for pin in vuln fixed; do
  o=$($H/s-$pin-plain "stub-${pin}-n16-41" 2>&1); rc=$?
  assert_case "safe-$pin" "$o" 1 "WRITE_OFF=88 WRITE_LEN=40 BYTES=$sixteen41"
done
# 7. Real pinned AES-SIV: valid ciphertext beyond the declared 104-byte
# datagram is decrypted into 16 chosen bytes at offset 328. The vulnerable
# cursor advance leaves buf.left=16, so the parser still returns false after
# the OOB write; only the write is claimed.
o=$($H/r-vuln real-vuln 2>&1); rc=$?
assert_case real-crypto-chosen "$o" 1 \
  'PLAIN_OFF=328 PLAIN=4142434445464748494a4b4c4d4e4f50'
printf '%s\n' "$o" > "$E/real-vuln.txt"
# 8. Fixed pin rejects before decrypt: ciphertext payload at the same offset
# is unchanged from the value printed by the encryptor.
o=$($H/r-fixed real-fixed 2>&1); rc=$?
payload=$(printf '%s\n' "$o" | sed -n 's/.*ENC_PAYLOAD=\([0-9a-f]*\).*/\1/p')
assert_case real-crypto-fixed "$o" 1 \
  'FN_RC=0' "PLAIN_OFF=328 PLAIN=$payload"
printf '%s\n' "$o" > "$E/real-fixed.txt"
printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
