#!/bin/sh
# fontforge2shell W23: third allocation state (tcache disabled) code-pointer sweep.
# Repeats the W15 negative-glyph write-window scan with
# GLIBC_TUNABLES=glibc.malloc.tcache_count=0, which changes the glibc heap
# layout without a new build. Asserts the allocator state actually changed
# (encs moved against the untuned baseline in the same tree) and that the
# scan class is unchanged: no live code pointer in the reachable window.
#
# Prerequisite: build-plain and build-nopie built by replay-real.sh and
# replay-nonpie.sh. Offline; no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 2
[ -x build-plain/bin/fontforge ] || { echo 'missing build-plain; run replay-real.sh first' >&2; exit 2; }
[ -x build-nopie/bin/fontforge ] || { echo 'missing build-nopie; run replay-nonpie.sh first' >&2; exit 2; }

printf 'New()\nImport("%s/truncated.pcf")\n' "$PWD" > w23-import.ff

make_cmd() {
    # $1 = mode (nopie|pie), $2 = output label (base|notcache)
    cat > "gdb-w23-$1-$2.cmd" <<EOF
set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script w23-import.ff
printf "W23-$2 encs=%p glyph=%d i=%d\\n", encs, glyph, i
dump binary memory /tmp/ff2s-w23-$1-$2.bin (char*)encs-131072 (char*)encs
info proc mappings
quit
EOF
}

for mode in nopie pie; do
    if [ "$mode" = nopie ]; then bin=build-nopie/bin/fontforge; else bin=build-plain/bin/fontforge; fi
    make_cmd "$mode" base
    make_cmd "$mode" notcache
    gdb -q -batch -x "gdb-w23-$mode-base.cmd" "./$bin" > "gdb-w23-$mode-base.out" 2>&1
    GLIBC_TUNABLES=glibc.malloc.tcache_count=0 \
        gdb -q -batch -x "gdb-w23-$mode-notcache.cmd" "./$bin" > "gdb-w23-$mode-notcache.out" 2>&1
    python3 scan-w15.py /tmp/ff2s-w23-$mode-notcache.bin "gdb-w23-$mode-notcache.out" "$bin" > "scan-w23-$mode.out"
done

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }

for mode in nopie pie; do
    check "$mode baseline breakpoint reached" has "W23-base encs=" "gdb-w23-$mode-base.out"
    check "$mode notcache breakpoint reached" has "W23-notcache encs=" "gdb-w23-$mode-notcache.out"
    check "$mode vulnerable store is glyph=-1 i=3" has 'glyph=-1 i=3' "gdb-w23-$mode-notcache.out"
done

# The tunable must have changed the allocator state: encs differs from the
# untuned baseline in the same build tree. Compare the pointer tokens only.
encs_changed() {
    mode=$1
    b=$(grep -oE 'W23-base encs=0x[0-9a-f]+' "gdb-w23-$mode-base.out" | head -1)
    n=$(grep -oE 'W23-notcache encs=0x[0-9a-f]+' "gdb-w23-$mode-notcache.out" | head -1)
    [ -n "$b" ] && [ -n "$n" ] && [ "$b" != "$n" ]
}
check 'nopie allocator state changed (encs moved)' encs_changed nopie
check 'pie allocator state changed (encs moved)' encs_changed pie

check 'nopie window still has no code-pointer candidates' has 'RESULT ASCII_ONLY' scan-w23-nopie.out
check 'nopie candidate count bounded (path-sensitive)' grep -qE 'CAND_COUNT [0-8]$' scan-w23-nopie.out
check 'pie window still has no candidates at all' has 'RESULT NONE' scan-w23-pie.out
check 'pie candidate count zero' has 'CAND_COUNT 0' scan-w23-pie.out

echo '=== encs tokens (allocator-state evidence) ==='
for mode in nopie pie; do
    printf '%s base: ' "$mode"; grep -oE 'W23-base encs=0x[0-9a-f]+ glyph=-?[0-9]+ i=[0-9]+' "gdb-w23-$mode-base.out" | head -1
    printf '%s notcache: ' "$mode"; grep -oE 'W23-notcache encs=0x[0-9a-f]+ glyph=-?[0-9]+ i=[0-9]+' "gdb-w23-$mode-notcache.out" | head -1
done
echo '=== normalized evidence hashes ==='
sha256sum scan-w23-nopie.out scan-w23-pie.out gdb-w23-nopie-base.out gdb-w23-nopie-notcache.out gdb-w23-pie-base.out gdb-w23-pie-notcache.out

echo "REPLAY_W23_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
