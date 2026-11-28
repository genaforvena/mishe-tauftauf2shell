#!/bin/sh
# Behavioral checks for the pinned Qt index-copy block. Loopback/network unused.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null
for arm in vuln fixed; do
    test -x "harness/gen/qtindex.$arm.asan" || { echo "run harness/build.sh first"; exit 1; }
    test -x "harness/gen/qtindex.$arm.plain" || { echo "run harness/build.sh first"; exit 1; }
done
mkdir -p evidence
pass=0
fail=0
check() {
    if [ "$1" -eq 1 ]; then pass=$((pass + 1)); echo "PASS $2"
    else fail=$((fail + 1)); echo "FAIL $2"; fi
}
run() {
    name=$1; shift
    set +e
    ASAN_OPTIONS=detect_leaks=0 "$@" > "evidence/$name.raw" 2>&1
    echo $? > "evidence/$name.rc"
    set -e
}
stable() {
    sed -E -e 's/==[0-9]+==//g' \
        -e '/ERROR: AddressSanitizer|SUMMARY/ s/0x[0-9a-f]+/ADDR/g' \
        -e 's#[^ ]*/harness/main.cpp#harness/main.cpp#g' \
        "evidence/$1.raw" | grep -E \
        'QTINDEX|RETURN|ERROR: AddressSanitizer|WRITE of size|located .*bytes|SUMMARY' \
        > "evidence/$1.stable" || true
}

run vuln-odd-asan harness/gen/qtindex.vuln.asan vuln heap ushort 5 0x4141
run fixed-odd-asan harness/gen/qtindex.fixed.asan fixed heap ushort 5 0x4141
run vuln-even-asan harness/gen/qtindex.vuln.asan vuln heap ushort 6 0x4242
run vuln-uint-asan harness/gen/qtindex.vuln.asan vuln heap uint 5 0x4343
run vuln-max-asan harness/gen/qtindex.vuln.asan vuln heap ushort 65535 0xffff
run vuln-odd-slab harness/gen/qtindex.vuln.plain vuln slab ushort 5 0x4141
run fixed-odd-slab harness/gen/qtindex.fixed.plain fixed slab ushort 5 0x4141
run vuln-even-slab harness/gen/qtindex.vuln.plain vuln slab ushort 6 0x4242
run vuln-max-slab harness/gen/qtindex.vuln.plain vuln slab ushort 65535 0xffff
for name in vuln-odd-asan fixed-odd-asan vuln-even-asan vuln-uint-asan \
            vuln-max-asan vuln-odd-slab fixed-odd-slab vuln-even-slab vuln-max-slab; do
    stable "$name"
done

check "$(grep -c 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/vuln-odd-asan.stable)" vuln-odd-asan-overflow
check "$(grep -c 'WRITE of size 10' evidence/vuln-odd-asan.stable)" vuln-odd-asan-write-size
check "$(grep -c '0 bytes after' evidence/vuln-odd-asan.stable)" vuln-odd-asan-region-end
check "$(grep -c 'ERROR: AddressSanitizer' evidence/fixed-odd-asan.stable | grep -c '^0$')" fixed-odd-asan-clean
check "$(grep -c 'RETURN slots=3 index_type=0' evidence/fixed-odd-asan.stable)" fixed-odd-rounded-up
check "$(grep -c 'ERROR: AddressSanitizer' evidence/vuln-even-asan.stable | grep -c '^0$')" vuln-even-asan-clean
check "$(grep -c 'RETURN slots=3 index_type=0' evidence/vuln-even-asan.stable)" vuln-even-slots
check "$(grep -c 'ERROR: AddressSanitizer' evidence/vuln-uint-asan.stable | grep -c '^0$')" vuln-uint-asan-clean
check "$(grep -c 'RETURN slots=5 index_type=1' evidence/vuln-uint-asan.stable)" vuln-uint-slots
check "$(grep -c 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/vuln-max-asan.stable)" vuln-max-asan-overflow
check "$(grep -c 'WRITE of size 131070' evidence/vuln-max-asan.stable)" vuln-max-asan-write-size
check "$(grep -c 'RETURN slots=2 index_type=0 victim=0x4141' evidence/vuln-odd-slab.stable)" vuln-odd-chosen-victim
check "$(grep -c 'RETURN slots=3 index_type=0 victim=0xefef' evidence/fixed-odd-slab.stable)" fixed-odd-victim-intact
check "$(grep -c 'RETURN slots=3 index_type=0 victim=0xefef' evidence/vuln-even-slab.stable)" vuln-even-victim-intact
check "$(grep -c 'RETURN slots=32767 index_type=0 victim=0xffff' evidence/vuln-max-slab.stable)" vuln-max-chosen-victim
check "$(sha256sum -c SHA256SUMS 2>/dev/null | grep -c ': OK$' | grep -c '^5$')" source-pins
sha256sum evidence/*.stable > evidence/SHA256SUMS
if [ "$fail" -eq 0 ]; then echo "RUN_ALL_OK $pass PASS / $fail FAIL"
else echo "RUN_ALL_FAIL $pass PASS / $fail FAIL"; exit 1; fi
