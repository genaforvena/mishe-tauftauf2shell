#!/usr/bin/env bash
# Replay: verify pinned tarballs and fix patch, extract the two verbatim pinned
# NetHandler functions from each tag, build ASan/plain controls, drive a
# loopback socketpair, assert the two-stage write, and hash normalized logs.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
L="$(cd "$H/.." && pwd)"
P="$L/pins"
E="$L/evidence"
mkdir -p "$E" "$L/src" "$H/gen-vuln" "$H/gen-fixed"

cd "$P"
sha256sum -c <<'EOF'
29b3b97fa240b2aa681e7935afb3a8aa65831ea7e669813730acfa25810926fb  bzflag-v2.4.30.tar.gz
86a5ded5a039185fee76e6ad65a68554e40cfe7cad5acbd9b1635821a546a7b7  bzflag-v2.4.32.tar.gz
441efea0348adde9f074af5a3b224c0db9c136a53097f0685996e260d875205a  fix-8e501d6.patch
EOF
cd "$L"
for v in 2.4.30 2.4.32; do
  [ -d "src/bzflag-$v" ] || tar xzf "pins/bzflag-v$v.tar.gz" -C src
done
# The fixed tag must carry both upstream guards; the patch must be the exact
# one-hunk-plus-comments delta from the vulnerable file.
grep -q 'if (len > MaxPacketLen - 4)' src/bzflag-2.4.32/src/game/NetHandler.cxx
grep -q 'if ((tcplen < 0) || ((size_t)tcplen > sizeof(tcpmsg))' src/bzflag-2.4.32/src/game/NetHandler.cxx

python3 "$H/gen_functions.py" "$L/src/bzflag-2.4.30/src/game/NetHandler.cxx" "$H/gen-vuln/net_functions.inc"
python3 "$H/gen_functions.py" "$L/src/bzflag-2.4.32/src/game/NetHandler.cxx" "$H/gen-fixed/net_functions.inc"

build () {
  local tag="$1" flags="$2" out="$3"
  # shellcheck disable=SC2086
  g++ -std=c++11 -g -O0 -fno-omit-frame-pointer $flags \
    -I"$H/gen-$tag" "$H/harness.cpp" -o "$H/$out"
}
build vuln "-fsanitize=address" bzflag-vuln-asan
build fixed "-fsanitize=address" bzflag-fixed-asan
build vuln "-DHARNESS_PLAIN_READBACK" bzflag-vuln-plain
build fixed "-DHARNESS_PLAIN_READBACK" bzflag-fixed-plain

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
  ASAN_OPTIONS=detect_leaks=0 "$H/$bin" >"$E/raw-$name.log" 2>&1
  echo $? >"$E/raw-$name.rc"
  set -e
  norm "$E/raw-$name.log" >"$E/norm-$name.log"
}
run bzflag-vuln-asan vuln-asan
run bzflag-fixed-asan fixed-asan
run bzflag-vuln-plain vuln-plain
run bzflag-fixed-plain fixed-plain

fail=0
check () { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "vuln ASan use-after-poison" "grep -q 'ERROR: AddressSanitizer: use-after-poison' '$E/norm-vuln-asan.log'"
check "vuln ASan WRITE" "grep -q 'WRITE of size 64' '$E/norm-vuln-asan.log'"
check "vuln ASan pinned recv frame" "grep -q 'NetHandler::receive' '$E/norm-vuln-asan.log' && grep -q 'gen-vuln/net_functions.inc:69' '$E/norm-vuln-asan.log'"
check "vuln ASan nonzero rc" "[ \"\$(cat '$E/raw-vuln-asan.rc')\" -ne 0 ]"
check "fixed ASan clean" "! grep -q 'ERROR: AddressSanitizer' '$E/norm-fixed-asan.log'"
check "fixed ASan rc0" "[ \"\$(cat '$E/raw-fixed-asan.rc')\" -eq 0 ]"
check "stage1 corrupt tcplen" "grep -q 'stage1_status=1 stage1_tcplen=-3072' '$E/norm-vuln-plain.log'"
check "stage2 chosen offset" "grep -q 'stage2_offset=-3072' '$E/norm-vuln-plain.log'"
check "chosen bytes 5a" "grep -q 'readback+0=5a5a5a5a5a5a5a5a' '$E/norm-vuln-plain.log'"
check "chosen bytes 41" "grep -q 'readback+16=4141414141414141' '$E/norm-vuln-plain.log'"
check "chosen bytes 42" "grep -q 'readback+32=4242424242424242' '$E/norm-vuln-plain.log'"
check "chosen bytes 43" "grep -q 'readback+48=4343434343434343' '$E/norm-vuln-plain.log'"
check "fixed rejects huge length" "grep -q 'stage1_status=2 stage1_tcplen=4' '$E/norm-fixed-plain.log'"
check "fixed no chosen readback" "! grep -q 'readback+0=5a5a5a5a' '$E/norm-fixed-plain.log'"

sha256sum "$E"/norm-*.log | sed "s#$E/##" > "$L/EVIDENCE_HASHES.txt"
cat "$L/EVIDENCE_HASHES.txt"
exit "$fail"
