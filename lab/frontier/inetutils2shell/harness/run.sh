#!/usr/bin/env bash
# Verify pins, extract the verbatim pinned SLC functions, build vulnerable and
# fixed ASan/plain variants, assert the global OOB write and chosen readback.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
L="$(cd "$H/.." && pwd)"
P="$L/pins"
E="$L/evidence"
mkdir -p "$E" "$L/src" "$H/gen-vuln" "$H/gen-fixed"

cd "$P"
sha256sum -c <<'EOF'
a156be1cde3c5c0ffefc262180d9369a60484087907aa554c62787d2f40ec086  inetutils-2.7.tar.gz
57b3cf4f77555992881e5ba2a09a63b05aa2c56342a60ed4305b5f45938390b5  inetutils-2.8.tar.gz
5729c658790c422e5b1301f14de046f791a2ad56ab8368d45e9784fcf891d988  fix-slc.patch
EOF
cd "$L"
for v in 2.7 2.8; do
  [ -d "src/inetutils-$v" ] || tar xzf "pins/inetutils-$v.tar.gz" -C src
done
grep -q 'if (slcbuf + sizeof slcbuf - slcptr <= 6)' src/inetutils-2.8/telnetd/slc.c
! grep -q 'slcbuf + sizeof slcbuf - slcptr' src/inetutils-2.7/telnetd/slc.c
python3 "$H/gen_slc.py" "$L/src/inetutils-2.7/telnetd/slc.c" "$H/gen-vuln/slc_functions.inc"
python3 "$H/gen_slc.py" "$L/src/inetutils-2.8/telnetd/slc.c" "$H/gen-fixed/slc_functions.inc"

build () {
  local tag="$1" flags="$2" out="$3"
  # shellcheck disable=SC2086
  cc -std=c11 -g -O0 -fno-omit-frame-pointer $flags -I"$H/gen-$tag" \
    "$H/harness.c" -o "$H/$out"
}
build vuln "-fsanitize=address" slc-vuln-asan
build fixed "-fsanitize=address" slc-fixed-asan
build vuln "" slc-vuln-plain
build fixed "" slc-fixed-plain

norm () {
  sed -E -e 's/==[0-9]+==/==PID==/g' \
         -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
         -e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
         -e "s|$H|HARNESS|g" -e "s|$L|LAB|g" \
         -e 's/^[[:space:]]*#[0-9]+ 0xADDR /#FRAME /' "$1"
}
run () {
  local bin="$1" name="$2"
  set +e
  ASAN_OPTIONS=detect_leaks=0 "$H/$bin" >"$E/raw-$name.log" 2>&1
  echo $? >"$E/raw-$name.rc"
  set -e
  norm "$E/raw-$name.log" >"$E/norm-$name.log"
}
run slc-vuln-asan vuln-asan
run slc-fixed-asan fixed-asan
run slc-vuln-plain vuln-plain
run slc-fixed-plain fixed-plain

fail=0
check () { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "vuln ASan global overflow" "grep -q 'ERROR: AddressSanitizer: global-buffer-overflow' '$E/norm-vuln-asan.log'"
check "vuln ASan WRITE" "grep -q 'WRITE of size 1' '$E/norm-vuln-asan.log'"
check "vuln ASan add_slc frame" "grep -q 'gen-vuln/slc_functions.inc' '$E/norm-vuln-asan.log' && grep -q 'add_slc' '$E/norm-vuln-asan.log'"
check "vuln ASan nonzero rc" "[ \"\$(cat '$E/raw-vuln-asan.rc')\" -ne 0 ]"
check "fixed ASan clean" "! grep -q 'ERROR: AddressSanitizer' '$E/norm-fixed-asan.log'"
check "fixed ASan rc0" "[ \"\$(cat '$E/raw-fixed-asan.rc')\" -eq 0 ]"
check "vuln readback chosen bytes" "grep -q 'readback+0=42415a42415a42415a' '$E/norm-vuln-plain.log'"
check "fixed readback not reached" "! grep -q 'readback+0=42415a' '$E/norm-fixed-plain.log'"

sha256sum "$E"/norm-*.log | sed "s#$E/##" > "$L/EVIDENCE_HASHES.txt"
cat "$L/EVIDENCE_HASHES.txt"
exit "$fail"
