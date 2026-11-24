#!/bin/sh
# Control for plain-proof.sh: same loopback RR attack against the locally
# patched real tree.  The fix clamps i to MAX_IPOPTLEN/hlen, so rc4_sbox
# (old_rr+0x40) must NOT receive the chosen marker.  Loopback only.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
rm -f plain.pid evidence/plain-fixed-gdb.out evidence/plain-fixed-proof.out

FIXED_SHA=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
if [ ! -x plain-fixed-src/hping3 ]; then
    [ -d plain-src ] || { echo "build plain-src first"; exit 2; }
    rm -rf plain-fixed-src
    cp -a plain-src plain-fixed-src
    cp plain-src/display_ipopt.c plain-fixed-src/display_ipopt.c
    patch -s -o /tmp/w2-fixed-display.c plain-fixed-src/display_ipopt.c < ../pinned/fix.patch
    cp /tmp/w2-fixed-display.c plain-fixed-src/display_ipopt.c
    ( cd plain-fixed-src && make clean >/dev/null 2>&1 &&
      make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' >../plain-fixed-build.log 2>&1 ) || {
        echo "fixed build failed"; exit 2; }
fi
[ "$(sha256sum plain-fixed-src/display_ipopt.c | cut -d' ' -f1)" = "$FIXED_SHA" ] || {
    echo "fix.patch not applied to plain-fixed-src"; exit 2; }
OLD_RR_LO=$(nm -n -S --defined-only plain-fixed-src/hping3 | awk '/ old_rr\.0$/{print $1}')
[ -n "$OLD_RR_LO" ] || { echo "no old_rr symbol"; exit 2; }

sudo -n sh -c 'echo $$ > plain.pid; exec ./plain-fixed-src/hping3 -D -1 -G -I lo -c 20 -i 1 127.0.0.2' \
    > evidence/plain-fixed-run.out 2>&1 &
hp=$!
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s plain.pid ] && break
    sleep 0.1
done
pid=$(cat plain.pid 2>/dev/null || echo 0)
[ "$pid" -gt 0 ] || { echo "no hping pid"; exit 2; }
echo "fixed hping pid=$pid"
sudo -n python3 inject_rr_plain.py --pid "$pid" --ptr 255 --rr-len 255 --count 3 --gap 0.15
sleep 0.4
mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"
addr=$(printf '0x%x' "$(( $base + 0x$OLD_RR_LO ))")
echo "pie_base=$base old_rr_link=$OLD_RR_LO old_rr_runtime=$addr"
sudo -n gdb -q -batch -p "$pid" \
    -ex "x/120xb $addr" \
    -ex 'info address rc4_sbox' \
    > evidence/plain-fixed-gdb.out 2>&1
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null
python3 check_plain.py baseline evidence/plain-fixed-gdb.out > evidence/plain-fixed-proof.out
cat evidence/plain-fixed-proof.out
grep -q '^PLAIN SUMMARY: .* PASS' evidence/plain-fixed-proof.out && exit 0 || exit 1
