#!/bin/sh
# W210: even after re-deriving the W202 heap-layout fixed point for the
# shipped `exrcheck -s -c` in-memory stream mode, the file-chosen pointer does
# not land in the live attribute slot and no command runs.  This is a bounded
# negative over the swept (dest, slot) family, not a proof for every mode.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'src/openexr-3.5.2/src/bin/exrcheck/main.cpp bff9a108e6c1ab14c0b303dd05a06413774e1e8b8ad73103e748de91b491b5f6' \
    'src/openexr-3.5.2/src/lib/OpenEXRUtil/ImfCheckFile.cpp 48b68e0fbab0644bf027f74251e2113f1ea311f9f6fc665eea964b8c350029ef' \
    'src/openexr-3.5.2/src/lib/OpenEXRCore/internal_zstd.c 736dad696b6263fd5f715ccf1d93ac7104dc5f50994a769046e586af828abcea' \
    'cases/p209-stream-chain.exr 2e6d246c7842c87d6038917b26452ee7c96849906021cc557eba6c2708e2da19' \
    'evidence/w210-sweep.log 5bff8dc74f7125f88c32ccceba7025826154cf1b4f8860fec6ee3ae836e5110e'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
MARKER=/tmp/w202m
trap 'rm -f "$RAW" "$MARKER"' EXIT

# The sweep log records the measured fixed point and the absence of any other
# fixed point in the scanned family.
grep -q 'dest=0x55555582a6f0 slot=1088 -> 0x55555582a6f0/1088 FIX' evidence/w210-sweep.log
grep -q '^FIXED_POINTS \[(93824995206896, 1088)\]$' evidence/w210-sweep.log

# The sink is still reached in stream mode with the recalibrated file.
set +e
timeout 20 env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    ./build-vuln-asan/bin/exrcheck -s -c cases/p209-stream-chain.exr > "$RAW" 2>&1
asan_rc=$?
set -e
test "$asan_rc" -ne 0
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$RAW"
grep -q 'READ of size 3072' "$RAW"
grep -q 'internal_zstd.c:472' "$RAW"

# Plain ASLR-off runs: no command side effect.
i=0
while test "$i" -lt 3; do
    rm -f "$MARKER"
    set +e
    timeout 20 setarch "$(uname -m)" -R ./build-vuln-plain/bin/exrcheck -s -c \
        cases/p209-stream-chain.exr > "$RAW" 2>&1
    plain_rc=$?
    set -e
    test "$plain_rc" -eq 139
    test ! -f "$MARKER"
    printf 'PLAIN_RUN_%d rc=%d marker=absent\n' "$((i + 1))" "$plain_rc"
    i=$((i + 1))
done

# At the destroy site, the live slot does not hold the forged attribute
# address even though the fixed point predicted that slot's address.
rm -f "$MARKER"
timeout 40 gdb -q -batch \
    -ex 'set args -s -c cases/p209-stream-chain.exr' \
    -ex 'set disable-randomization on' \
    -ex 'break attributes.c:305' -ex 'run' \
    -ex 'printf "SLOT=%p EXPECTED=%p TYPE=%d\n", list->entries[0], (void*)0x55555582ab70, ((exr_attribute_t*)0x55555582ab70)->type' \
    ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1
grep -q '^SLOT=0x900000511 EXPECTED=0x55555582ab70 TYPE=31$' "$RAW"
if grep -q '^CTXT=' "$RAW" || grep -q '^SYSTEM_RDI=' "$RAW"; then
    echo 'chain unexpectedly reached the command call' >&2
    exit 1
fi
test ! -f "$MARKER"

{
    echo 'MODE=exrcheck -s -c, W202 chain re-derived by gdb fixed point'
    echo 'SWEEP_FIXPOINT=dest=0x55555582a6f0 slot=1088 (only fixed point in scan)'
    echo "ASAN_SINK_RC=$asan_rc heap-buffer-overflow READ=3072 internal_zstd.c:472=1"
    echo 'ASLR=off in plain and gdb runs (setarch -R / disable-randomization on)'
    echo 'SLOT=0x900000511 EXPECTED=0x55555582ab70 TYPE=31'
    echo 'CHAIN_COMMAND=not reached MARKER=absent'
    echo 'RESULT PASS'
} > evidence/w210-stream-chain-negative.out

printf 'RESULT PASS\n'
sha256sum evidence/w210-stream-chain-negative.out
