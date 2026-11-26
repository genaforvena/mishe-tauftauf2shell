#!/bin/sh
# Replay the sngrep CVE-2026-121943 verbatim-slice harness. No network, no
# sockets, no pcap: the driver calls sip_validate_packet() with a local payload.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p runs

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has()  { grep -Fq -- "$2" "$1" 2>/dev/null; }

if (cd pins && sha256sum -c PIN_HASHES.txt) >runs/pins.log 2>&1; then
    ok 'four pins sha256-match manifest'
else
    bad 'pin hashes'
fi

if python3 gen_sink.py >runs/generate.log 2>&1; then
    ok 'verbatim slices generated with pinned-line assertions'
else
    bad 'generate sinks'
fi

if python3 -c '
from pathlib import Path
for out, pin in (("h/sink_vuln.cpp", "pins/sip.c.vuln"), ("h/sink_fixed.cpp", "pins/sip.c.fixed")):
    body = "\n".join(Path(pin).read_text().splitlines()[315:341]) + "\n"
    assert body in Path(out).read_text(), out
print("verbatim sink slices match raw pinned lines 316-341")
' >runs/verbatim.log 2>&1; then
    ok 'verbatim sink slices match raw pinned lines'
else
    bad 'verbatim sink slices'
fi

CXX=${CXX:-g++}
CC=${CC:-clang}
$CXX -g -O1 -fsanitize=address -fno-omit-frame-pointer -o h/asan-vuln h/sink_vuln.cpp 2>runs/build-asan-vuln.log && ok 'GCC ASan vulnerable build' || bad 'GCC ASan vulnerable build'
$CXX -g -O1 -fsanitize=address -fno-omit-frame-pointer -o h/asan-fixed h/sink_fixed.cpp 2>runs/build-asan-fixed.log && ok 'GCC ASan fixed build' || bad 'GCC ASan fixed build'
$CXX -g -O1 -o h/plain-vuln h/sink_vuln.cpp 2>runs/build-plain.log && ok 'GCC plain vulnerable build' || bad 'GCC plain vulnerable build'
$CC -g -O1 -fsanitize=address -fno-omit-frame-pointer -o h/clang-asan-vuln h/sink_vuln.cpp 2>runs/build-clang.log && ok 'clang ASan vulnerable build' || bad 'clang ASan vulnerable build'

# Attack: exactly MAX_SIP_PAYLOAD (10240) non-NUL bytes fills the 10240-byte
# stack buffer; regexec strlen reads past the terminator-less array.
./h/asan-vuln 10240 >runs/asan-vuln-10240.out 2>&1; rc=$?
if [ "$rc" -eq 1 ] && has runs/asan-vuln-10240.out 'stack-buffer-overflow' \
   && has runs/asan-vuln-10240.out 'READ of size 10241' \
   && has runs/asan-vuln-10240.out 'src/sip.c:338' \
   && has runs/asan-vuln-10240.out "'payload' (line 320)"; then
    ok 'GCC ASan stack OOB READ at raw sip.c:338, payload at :320'
else
    bad "GCC ASan attack trace rc=$rc"
fi

./h/asan-fixed 10240 >runs/asan-fixed-10240.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! has runs/asan-fixed-10240.out 'AddressSanitizer' \
   && has runs/asan-fixed-10240.out 'SIP_VALIDATE_RC=0'; then
    ok 'fixed pin MAX_SIP_PAYLOAD+1 control clean'
else
    bad "fixed pin control rc=$rc"
fi

./h/asan-vuln 10239 >runs/asan-vuln-10239-safe.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! has runs/asan-vuln-10239-safe.out 'AddressSanitizer'; then
    ok '10239-byte safe vector clean on vulnerable pin'
else
    bad "safe vector rc=$rc"
fi

./h/asan-vuln 10241 >runs/asan-vuln-10241-guard.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! has runs/asan-vuln-10241-guard.out 'AddressSanitizer'; then
    ok '10241-byte guard rejects before copy'
else
    bad "oversize guard rc=$rc"
fi

./h/plain-vuln 10240 >runs/plain-vuln-10240.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && has runs/plain-vuln-10240.out 'SIP_VALIDATE_RC=0'; then
    ok 'plain vulnerable attack exits 0 (rung 1/2 negative preserved)'
else
    bad "plain vulnerable attack rc=$rc"
fi

./h/clang-asan-vuln 10240 >runs/clang-asan-vuln-10240.out 2>&1; rc=$?
if [ "$rc" -eq 1 ] && has runs/clang-asan-vuln-10240.out 'stack-buffer-overflow' \
   && has runs/clang-asan-vuln-10240.out 'src/sip.c:338'; then
    ok 'clang ASan reproduces the same read'
else
    bad "clang ASan attack rc=$rc"
fi

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
