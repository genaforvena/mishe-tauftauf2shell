#!/usr/bin/env bash
# Verify pinned pppd 2.5.3 / 2.5.4, extract lcp_reqci() verbatim from each,
# build vuln/fixed ASan+plain variants and assert the nak_buffer overflow,
# chosen-byte control, safe-input control and fixed/safe clean controls.
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
L="$(cd "$H/.." && pwd)"
P="$L/pins"
E="$L/evidence"
mkdir -p "$E" "$L/src" "$L/src-fixed" "$H/gen-vuln" "$H/gen-fixed" "$H/inc"

cd "$P"
sha256sum -c <<'EOF'
96f962b9f9411ee4a75da34e5b6177eaec4dce0527af009891210641e0b74edf  ppp-2.5.3.tar.gz
379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31  ppp-2.5.4.tar.gz
4fa8b23ad1238a981215c8d9b312d92458146b047d92ca9601e6d81c5a42ac58  fix-1baf2ac.patch
8593bced5e3722c53a63922760fc760f59d18072544fae9d0f4046ba036ffaad  fix-cc8b00c.patch
EOF

cd "$L"
[ -d src/ppp-project-ppp-0cfdb73 ] || tar xzf pins/ppp-2.5.3.tar.gz -C src
[ -d src-fixed/ppp-2.5.4 ] || tar xzf pins/ppp-2.5.4.tar.gz -C src-fixed
V=src/ppp-project-ppp-0cfdb73
F=src-fixed/ppp-2.5.4

# Generated pppdconf.h: all features off (verbatim template, all #undef).
cp "$V/pppd/pppdconf.h.in" "$H/inc/pppdconf.h"
for tag in vuln fixed; do
  cp "$H/harness.c" "$H/gen-$tag/harness.c"
done
python3 "$H/gen_lcp.py" "$V/pppd/lcp.c" "$H/gen-vuln/lcp_functions.inc"
python3 "$H/gen_lcp.py" "$F/pppd/lcp.c" "$H/gen-fixed/lcp_functions.inc"
grep -q 'if (seenci\[citype\])' "$F/pppd/lcp.c"
grep -q 'nakp - nak_buffer > PPP_MRU' "$F/pppd/lcp.c"
! grep -q 'if (seenci\[citype\])' "$V/pppd/lcp.c"

build () {
  local tag="$1" cc="$2" flags="$3" defs="$4" out="$5"
  local root="$V" ; [ "$tag" = fixed ] && root="$F"
  # shellcheck disable=SC2086
  "$cc" -std=gnu11 -g -O0 -fno-omit-frame-pointer $flags $defs \
    -I"$H/inc" -I"$L/$root/pppd" -I"$L/$root/include" -I"$L/$root" \
    "$H/gen-$tag/harness.c" -o "$H/$out"
}
build vuln  gcc    "-fsanitize=address" "" pppd-vuln-asan
build fixed gcc    "-fsanitize=address" "" pppd-fixed-asan
build vuln  gcc    "" "" pppd-vuln-plain
build fixed gcc    "" "" pppd-fixed-plain
build vuln  gcc    "" "-DCI_COUNT=2" pppd-vuln-safe
build fixed gcc    "" "-DCI_COUNT=2" pppd-fixed-safe
build vuln  gcc    "" "-DCHOSEN_MDTYPE=MDTYPE_MD5" pppd-vuln-alt
build vuln  clang  "-std=gnu89 -fsanitize=address" "" pppd-vuln-clang-asan
build fixed clang  "-std=gnu89 -fsanitize=address" "" pppd-fixed-clang-asan
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
for spec in "pppd-vuln-asan vuln-asan" "pppd-fixed-asan fixed-asan" \
            "pppd-vuln-clang-asan vuln-clang-asan" "pppd-fixed-clang-asan fixed-clang-asan" \
            "pppd-vuln-plain vuln-plain" "pppd-fixed-plain fixed-plain" \
            "pppd-vuln-safe vuln-safe" "pppd-fixed-safe fixed-safe" \
            "pppd-vuln-alt vuln-alt"; do
  run $spec
done

fail=0
check () { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "vuln gcc ASan global overflow" "grep -q 'ERROR: AddressSanitizer: global-buffer-overflow' '$E/norm-vuln-asan.log'"
check "vuln gcc ASan WRITE" "grep -q 'WRITE of size 1' '$E/norm-vuln-asan.log'"
check "vuln gcc ASan lcp_reqci frame" "grep -q 'gen-vuln/lcp_functions.inc' '$E/norm-vuln-asan.log' && grep -q 'lcp_reqci' '$E/norm-vuln-asan.log'"
check "vuln gcc ASan 0 bytes past nak_buffer" "grep -q '0 bytes after global variable .nak_buffer' '$E/norm-vuln-asan.log'"
check "fixed gcc ASan clean" "! grep -q 'ERROR: AddressSanitizer' '$E/norm-fixed-asan.log'"
check "vuln clang ASan overflow" "grep -q 'ERROR: AddressSanitizer: global-buffer-overflow' '$E/norm-vuln-clang-asan.log'"
check "fixed clang ASan clean" "! grep -q 'ERROR: AddressSanitizer' '$E/norm-fixed-clang-asan.log'"
check "vuln plain chosen-byte readback" "grep -q 'readback+1500=0305c223800305c2238' '$E/norm-vuln-plain.log'"
check "vuln plain alt chosen byte" "grep -q 'readback+1500=0305c223050305c2230' '$E/norm-vuln-alt.log'"
check "fixed plain no chosen bytes" "! grep -q 'readback+1500=0305c2238' '$E/norm-fixed-plain.log'"
check "vuln safe input in=8" "grep -q 'in=8 ' '$E/norm-vuln-safe.log'"
check "fixed safe input in=8" "grep -q 'in=8 ' '$E/norm-fixed-safe.log'"

sha256sum "$E"/norm-*.log | sed "s#$E/##" > "$L/EVIDENCE_HASHES.txt"
cat "$L/EVIDENCE_HASHES.txt"
exit "$fail"
