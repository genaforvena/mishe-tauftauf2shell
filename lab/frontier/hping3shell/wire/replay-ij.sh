#!/bin/sh
# One-command replay of the clang-build hp_rand.i/j index-control experiment.
# Builds both binaries from the provisioned pinned source; loopback only.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence compat/net
: > compat/net/bpf.h
SRC=${HPING_SRC:-../provision/hping-src}
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
[ -f "$SRC/display_ipopt.c" ] || { echo "HPING_SRC missing: $SRC"; exit 2; }
[ "$(sha256sum "$SRC/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || {
    echo "provisioned source is not the pinned bytes"; exit 2; }

build() {
    dir=$1; patched=$2
    [ -x "$dir/hping3" ] && return 0
    rm -rf "$dir"; cp -a "$SRC" "$dir"
    if [ "$patched" = 1 ]; then
        ( cd "$dir" && patch -p1 < ../../pinned/fix.patch >/dev/null ) || return 2
    fi
    ( cd "$dir" && ./configure --no-tcl >/dev/null 2>&1 && make clean >/dev/null 2>&1 &&
      make -j4 CC=clang CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
          >"../$(basename "$dir")-build.log" 2>&1 ) || return 2
}
build clang-src 0 || { echo "clang build failed"; exit 2; }
build clang-fixed-src 1 || { echo "clang fixed build failed"; exit 2; }
[ "$(sha256sum clang-src/display_ipopt.c | cut -d' ' -f1)" = "$PIN" ] || exit 2
[ "$(sha256sum clang-fixed-src/display_ipopt.c | cut -d' ' -f1)" = "$FIX" ] || exit 2

echo "STAGE baseline"
EXPECT=baseline FILL=0 I0=32 J0=128 RUN_TAG=ij-baseline \
    sh rng-ij-proof.sh > evidence/replay-ij-baseline.out 2>&1 || {
    tail -20 evidence/replay-ij-baseline.out; echo "baseline FAILED"; exit 1; }
tail -1 evidence/replay-ij-baseline.out

echo "STAGE attack"
EXPECT=attack FILL=0 I0=32 J0=128 RUN_TAG=ij-attack \
    sh rng-ij-proof.sh > evidence/replay-ij-attack.out 2>&1 || {
    tail -20 evidence/replay-ij-attack.out; echo "attack FAILED"; exit 1; }
tail -1 evidence/replay-ij-attack.out

echo "STAGE fixed"
EXPECT=fixed BIN=clang-fixed-src/hping3 FILL=0 I0=32 J0=128 RUN_TAG=ij-fixed \
    sh rng-ij-proof.sh > evidence/replay-ij-fixed.out 2>&1 || {
    tail -20 evidence/replay-ij-fixed.out; echo "fixed FAILED"; exit 1; }
tail -1 evidence/replay-ij-fixed.out

total=$(grep -h 'checks run' evidence/replay-ij-*.out | awk -F'[:, ]+' '{s+=$3} END{print s}')
echo "REPLAY_IJ_OK: $total checks"
[ "$total" -eq 15 ]
