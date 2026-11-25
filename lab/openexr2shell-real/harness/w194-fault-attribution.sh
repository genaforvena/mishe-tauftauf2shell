#!/bin/sh
# W194: one-command replay of fault attribution for the W193 PoCs.
# In the UNMODIFIED pinned 3.5.2 exrcheck -c, with ASLR explicitly ON,
# the first exr_attr_list_destroy dereference (attributes.c:305) reads
# E[0] = 0x555555828210, a stale absolute pointer baked into the W192
# source dump, not the file-chosen E[2].  The chosen word stays a live
# pointer field; the observed SIGSEGV is NOT attributed to it.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/make_poc_mixed_full.py 90f3f6fa759cfbd1453db7b161e2b6d8d67eba2b2e9978ea74b68f91d44d52c2' \
    'harness/w194-fault.cmd e7c77bd522c69348b83e854226253de7ce7c6c6c3ca6f56b416f3cc88d446129' \
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
        -ex "set args -c cases/p193-e0-$tag.exr" \
        -x harness/w194-fault.cmd \
        ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1 || true
    grep -q '^Disabling randomization of debuggee.s virtual address space is off\.$' "$RAW"
    grep -q '^LOOP i=0 entry=0x555555828210$' "$RAW"
    grep -q '^ENTRIES_DELTA=4320 NUM=11$' "$RAW"
    grep -q "^E\\[2\\]=0x$tag$tag$tag$tag\$" "$RAW"
    grep -q '^E\[0\]=0x0000555555828210$' "$RAW"
    grep -q '^E\[1\]=0x0000555555828280$' "$RAW"
    grep -q '^E\[3\]=0x0000555555828330$' "$RAW"
    grep -q 'mov    0x14(%r13),%eax' "$RAW"
    grep -q 'Cannot access memory at address 0x555555828210' "$RAW"

    {
        grep -E '^(Disabling|LOOP|ENTRIES_DELTA|E\[[0-9]+\]=)' "$RAW"
        grep -o 'mov    0x14(%r13),%eax' "$RAW"
        grep -o 'Cannot access memory at address 0x555555828210' "$RAW"
    } > "evidence/w194-fault-$tag.out"
done

set +e
./build-vuln-plain/bin/exrcheck -c cases/baseline.exr \
    > evidence/w194-valid.out 2>&1
valid_rc=$?
./build-fixed-plain/bin/exrcheck -c cases/p193-e0-4141.exr \
    > evidence/w194-fixed.out 2>&1
fixed_rc=$?
set -e
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
grep -q 'OK' evidence/w194-valid.out
grep -q 'bad' evidence/w194-fixed.out

printf 'RESULT PASS\n'
sha256sum evidence/w194-*.out
