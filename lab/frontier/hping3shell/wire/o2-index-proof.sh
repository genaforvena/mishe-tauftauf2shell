#!/bin/sh
# -O2 pinned hping on loopback: glibc fortify turns the crafted RR overflow
# into a detected abort before any global write.  GDB only reads i/j/sbox.
# NO_INJECT=1 gives a clean baseline; BIN/EXPECT_SHA give the fixed control.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
BIN=${BIN:-opt-src/hping3}
EXPECT_SHA=${EXPECT_SHA:-$SHA}
tag=${RUN_TAG:-attack}
[ "${NO_INJECT:-0}" = 1 ] && tag=baseline
run="evidence/o2-$tag-run.out"
gd="evidence/o2-$tag-gdb.out"
cfg="evidence/o2-$tag.gdb"
pidf="evidence/o2-$tag.pid"
SRC=${HPING_SRC:-../provision/hping-src}
[ "$(sha256sum "$SRC/display_ipopt.c" | cut -d' ' -f1)" = "$SHA" ] || {
    echo "pinned source hash mismatch"; exit 2; }
if [ ! -x "$BIN" ]; then
    [ -d "${BIN%/hping3}" ] || cp -a "$SRC" "${BIN%/hping3}"
    mkdir -p compat/net
    : > compat/net/bpf.h
    ( cd opt-src || exit 1
      [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
      make clean >/dev/null 2>&1
      make -j4 CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat' \
        >../o2-build.log 2>&1 ) || { echo "O2 build failed"; exit 2; }
fi
[ "$(sha256sum "${BIN%/hping3}/display_ipopt.c" | cut -d' ' -f1)" = "$EXPECT_SHA" ] || {
    echo "built source hash mismatch"; exit 2; }
rr=$(nm -n -S --defined-only "$BIN" | awk '/ old_rr\.0$/{print $1}')
ji=$(nm -n -S --defined-only "$BIN" | awk '/ j\.0$/{print $1; exit}')
ii=$(nm -n -S --defined-only "$BIN" | awk '/ i\.1$/{print $1; exit}')
sf=$(nm -n -S --defined-only "$BIN" | awk '/ rc4_seedflag$/{print $1; exit}')
sb=$(nm -n -S --defined-only "$BIN" | awk '/ rc4_sbox$/{print $1; exit}')
[ "$((0x$ji - 0x$rr))" = 64 ] && [ "$((0x$ii - 0x$rr))" = 68 ] &&
[ "$((0x$sf - 0x$rr))" = 72 ] && [ "$((0x$sb - 0x$rr))" = 96 ] || {
    echo "unexpected -O2 layout: old_rr=$rr j=$ji i=$ii seedflag=$sf sbox=$sb"; exit 2; }
echo "O2 LAYOUT old_rr=0x$rr j=0x$ji i=0x$ii seedflag=0x$sf sbox=0x$sb"
sudo -n rm -f "$pidf" "$run" "$gd"
: > "$run"; : > "$gd"
sudo -n sh -c "echo \$\$ > '$PWD/$pidf'; exec '$PWD/$BIN' -D -1 -G --rand-dest -I lo -c 24 -i 1 127.0.0.x" \
    > "$run" 2>&1 &
hp=$!
for x in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s "$pidf" ] && break
    sleep 0.1
done
pid=$(cat "$pidf" 2>/dev/null || echo 0)
[ "$pid" -gt 0 ] || { echo "no hping pid"; kill "$hp" 2>/dev/null; exit 2; }
mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"
jj=$(printf '0x%x' $((base + 0x$ji)))
xx=$(printf '0x%x' $((base + 0x$ii)))
ss=$(printf '0x%x' $((base + 0x$sb)))
cat > "$cfg" <<EOF
set pagination off
set confirm off
file $PWD/$BIN
break hp_rand
commands
silent
printf "STATE hit\\n"
x/wx $jj
x/wx $xx
x/256xb $ss
continue
end
attach $pid
c
EOF
echo "O2 RUN pid=$pid pie_base=$base"
timeout 30 sudo -n gdb -q -batch -x "$cfg" > "$gd" 2>&1 &
gp=$!
sleep 4
if [ "${NO_INJECT:-0}" = 1 ]; then
    echo "NO_INJECT=1: baseline"
else
    sudo -n python3 inject_rr_o2.py --pid "$pid" --count 3 --gap 0.15
fi
wait "$gp"
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null
if [ "${NO_INJECT:-0}" = 1 ]; then expect=baseline
elif [ -n "${EXPECT:-}" ]; then expect=$EXPECT
else expect=attack; fi
python3 check_o2.py "$gd" "$run" --expect "$expect" > "evidence/o2-$tag-proof.out"
cat "evidence/o2-$tag-proof.out"
grep -q 'O2 FORTIFY SUMMARY: .* PASS' "evidence/o2-$tag-proof.out" && exit 0 || exit 1
