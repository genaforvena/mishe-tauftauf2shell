#!/usr/bin/env bash
# Self-contained replay: verify pinned tarballs, extract, build the real pinned
# writer with ASan/plain, run vulnerable and fixed-caller controls, normalize,
# assert the ladder conditions, and write reproducible hashes.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
L="$(cd "$H/.." && pwd)"
P="$L/pins"
E="$L/evidence"
mkdir -p "$E" "$H/gen-vuln" "$H/gen-fixed" "$L/src"

cd "$P"
sha256sum -c <<'EOF'
0bc9271e675df12e9fb90c65fa6e21d1b291ac15602d97e42a861365b689bc07  p-net-v1.0.3.tar.gz
b512d3f83eeb6a1135fd4f3c972a12bb1b980db1a5df421ed5cdbedf38a1b87f  p-net-v1.0.4.tar.gz
249ac7d372383ac0b06f73959d63816dd0a4f8bba02689cb5bed2fb1f9ff71f8  fix-1c3b0b4.patch
EOF
cd "$L"
for v in 1.0.3 1.0.4; do
  [ -d "src/p-net-public-v$v" ] || tar xzf "pins/p-net-v$v.tar.gz" -C src
done
python3 "$H/gen_options.py" "$L/src/p-net-public-v1.0.3/pnet_options.h.in" "$H/gen-vuln/pnet_options.h"
python3 "$H/gen_options.py" "$L/src/p-net-public-v1.0.4/pnet_options.h.in" "$H/gen-fixed/pnet_options.h"

build () {
  local version="$1" tag="$2" shiftargs="$3" out="$4"
  local S="$L/src/p-net-public-v$version"
  # shellcheck disable=SC2086
  cc -g -O0 -fno-omit-frame-pointer $shiftargs \
    -I"$H/stubs" -I"$H/gen-$tag" -I"$S/src/device" -I"$S/src" \
    -I"$S/src/common" -I"$S/include" \
    "$H/harness.c" "$S/src/device/pf_block_reader.c" -o "$H/$out"
}

build 1.0.3 vuln "-fsanitize=address" pnet-vuln-asan
build 1.0.4 fixed "-fsanitize=address -DFIXED_CALLER" pnet-fixed-asan
build 1.0.3 vuln "-DHARNESS_READBACK" pnet-vuln-plain
build 1.0.4 fixed "-DFIXED_CALLER -DHARNESS_READBACK" pnet-fixed-plain

norm () {
  sed -E -e 's/==[0-9]+==/==PID==/g' \
         -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
         -e 's/^[[:space:]]*#[0-9]+ 0xADDR /#FRAME /' \
         -e 's/[0-9]+ ms\./N ms./g' \
         -e 's/process PID [0-9]+/process PID N/g' "$1"
}

run () {
  local bin="$1" name="$2"
  set +e
  "$H/$bin" >"$E/raw-$name.log" 2>&1
  echo $? >"$E/raw-$name.rc"
  set -e
  norm "$E/raw-$name.log" >"$E/norm-$name.log"
}

run pnet-vuln-asan vuln-asan
run pnet-fixed-asan fixed-asan
run pnet-vuln-plain vuln-plain
run pnet-fixed-plain fixed-plain

fail=0
check () { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "vuln ASan report" "grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' '$E/norm-vuln-asan.log'"
check "vuln ASan write" "grep -q 'WRITE of size' '$E/norm-vuln-asan.log'"
check "vuln real frame" "grep -q 'pf_get_mcr_request' '$E/norm-vuln-asan.log'"
check "vuln ASan rc" "[ \"\$(cat '$E/raw-vuln-asan.rc')\" -ne 0 ]"
check "fixed ASan clean" "! grep -q 'ERROR: AddressSanitizer' '$E/norm-fixed-asan.log'"
check "fixed ASan rc0" "[ \"\$(cat '$E/raw-fixed-asan.rc')\" -eq 0 ]"
check "fixed rejects" "grep -q 'reject: block 1, nbr_mcr=1, WRONG_BLOCK_COUNT' '$E/norm-fixed-plain.log'"
check "chosen scalar readback" "grep -q 'iocr=4142 protocol=43 resolution=44 timeout=4546 namelen=16' '$E/norm-vuln-plain.log'"
check "chosen name readback" "grep -q 'name=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a' '$E/norm-vuln-plain.log'"
check "chosen offset" "grep -q 'slot1_offset=252' '$E/norm-vuln-plain.log'"
check "fixed has no OOB readback" "! grep -q 'iocr=4142' '$E/norm-fixed-plain.log'"

sha256sum "$E"/norm-*.log | sed "s#$E/##" > "$L/EVIDENCE_HASHES.txt"
cat "$L/EVIDENCE_HASHES.txt"
exit "$fail"
