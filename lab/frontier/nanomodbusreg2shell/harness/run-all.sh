#!/bin/sh
# Rebuild all pinned arms and run loopback-only replays. Stable tokens only:
# no PIDs, ports, addresses or binary build IDs enter the summary hash.
set -eu
cd "$(dirname "$0")/.."
mkdir -p build evidence
CC=${CC:-gcc}
INC="-I src"
COMMON="-g -O0 -w $INC"
ASAN="-fsanitize=address -fno-omit-frame-pointer"
PLAIN="-fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -no-pie"

$CC $COMMON $ASAN src/nanomodbus-v1.22.0.c src/client-tcp.c -o build/example-asan
$CC $COMMON $ASAN src/nanomodbus-v1.22.0.c harness/client-wire.c -o build/min-asan
$CC $COMMON $ASAN src/nanomodbus-v1.22.1.c harness/client-wire.c -o build/min-fixed-asan
$CC $COMMON $PLAIN src/nanomodbus-v1.22.0.c harness/client-wire.c -o build/min-plain

address() {
    nm -n "$1" | awk '/ marker$/{print $1}'
}
memhex() {
    python3 -c 'import struct,sys;a=int(sys.argv[1],16);print("4343434343434343"+"0100000000000000"+struct.pack("<Q",a).hex())' "$1"
}

CHECKS=""
FAIL=0
check() {
    if grep -q "$2" "$1"; then
        CHECKS="$CHECKS
CHECK_OK $3"
    else
        CHECKS="$CHECKS
CHECK_FAIL $3"
        FAIL=$((FAIL + 1))
    fi
}
absent() {
    if grep -q "$2" "$1"; then
        CHECKS="$CHECKS
CHECK_FAIL $3"
        FAIL=$((FAIL + 1))
    else
        CHECKS="$CHECKS
CHECK_OK $3"
    fi
}

PIN_COUNT=$(sha256sum -c SHA256SUMS 2>/dev/null | awk '$2 == "OK" {n++} END {print n+0}')
echo "PIN_OK $PIN_COUNT"
[ "$PIN_COUNT" -eq 11 ] || FAIL=$((FAIL + 1))

python3 harness/replay.py build/example-asan example-asan-attack >/dev/null
check evidence/example-asan-attack.client.out 'stack-buffer-overflow' 'example-asan-overflow'
check evidence/example-asan-attack.client.out 'nanomodbus-v1.22.0.c:603' 'example-asan-pinned-sink'
check evidence/example-asan-attack.client.out 'client-tcp.c:83' 'example-upstream-caller'
check evidence/example-asan-attack.server.out 'SERVER_ATTACK_SENT' 'example-wire-sent'

python3 harness/replay.py build/min-asan min-asan-attack >/dev/null
check evidence/min-asan-attack.client.out 'WRITE of size 2' 'min-asan-write'
check evidence/min-asan-attack.client.out 'nanomodbus-v1.22.0.c:603' 'min-asan-pinned-sink'
check evidence/min-asan-attack.client.out 'read_two harness/client-wire.c' 'min-asan-caller'
check evidence/min-asan-attack.server.out 'SERVER_ATTACK_SENT' 'min-wire-sent'

python3 harness/replay.py build/min-fixed-asan min-fixed-attack >/dev/null
check evidence/min-fixed-attack.client.out 'READ_RC -2 REG0 0000 REG1 0000' 'fixed-rejects-attack'
absent evidence/min-fixed-attack.client.out 'AddressSanitizer' 'fixed-no-asan'

NMBS_COUNT=4 python3 harness/replay.py build/min-asan min-asan-safe >/dev/null
check evidence/min-asan-safe.client.out 'REG0 4141 REG1 4141' 'safe-byte-count'
absent evidence/min-asan-safe.client.out 'AddressSanitizer' 'safe-no-asan'

NMBS_BYTE=0x43 NMBS_GDB=harness/gdb-savedrip.cmd \
    python3 harness/replay.py build/min-plain min-plain-rip >/dev/null
check evidence/min-plain-rip.client.out 'Program received signal SIGSEGV' 'plain-rip-fault'
check evidence/min-plain-rip.client.out '0x4343434343434343 in ?? ()' 'plain-chosen-rip'

PLAIN_MEM=$(memhex "$(address build/min-plain)")
NMBS_MEM_HEX="$PLAIN_MEM" NMBS_BYTE=0x43 \
    python3 harness/replay.py build/min-plain min-plain-marker >/dev/null
check evidence/min-plain-marker.client.out 'BENIGN_MARKER' 'plain-chosen-address-exec'

FIXED_MEM=$(memhex "$(address build/min-fixed-asan)")
NMBS_MEM_HEX="$FIXED_MEM" NMBS_BYTE=0x43 \
    python3 harness/replay.py build/min-fixed-asan min-fixed-marker >/dev/null
check evidence/min-fixed-marker.client.out 'READ_RC -2 REG0 0000 REG1 0000' 'fixed-marker-reject'
absent evidence/min-fixed-marker.client.out 'BENIGN_MARKER' 'fixed-no-marker'

printf '%s\n' "$CHECKS" | grep -E '^CHECK_' || true
printf '%s\n' "$CHECKS" | grep -c '^CHECK_OK' | sed 's/^/RUN_ALL_OK /'
echo "RUN_ALL_FAIL $FAIL"
printf '%s\n' "$CHECKS" | grep -E '^CHECK_(OK|FAIL)' | sha256sum | awk '{print "SUMMARY_SHA256 " $1}'
[ "$FAIL" -eq 0 ]
