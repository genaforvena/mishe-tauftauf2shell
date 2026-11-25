#!/bin/sh
# One-command replay of the clang -O2 extension of the hp_rand.i/j write.
# Builds both binaries from the provisioned pinned source; loopback only.
set -u
PATCH=$PWD/../pinned/fix.patch
SRC=${HPING_SRC:-../provision/hping-src}
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
[ -f "$SRC/display_ipopt.c" ] || { echo "HPING_SRC missing: $SRC"; exit 2; }
[ "$(sha256sum "$SRC/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || {
    echo "provisioned source is not the pinned bytes"; exit 2; }

D=evidence/w11-o2
mkdir -p "$D/compat/net"
: > "$D/compat/net/bpf.h"

build() {
    dir=$1; patched=$2
    [ -x "$dir/hping3" ] && return 0
    rm -rf "$dir"; cp -a "$SRC" "$dir"
    if [ "$patched" = 1 ]; then
        ( cd "$dir" && patch -p1 < "$PATCH" >/dev/null ) || return 2
    fi
    ( cd "$dir" && ./configure --no-tcl >"../$(basename "$dir")-configure.log" 2>&1 &&
      make clean >/dev/null 2>&1 &&
      make -j4 CC=clang CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat' \
          >"../$(basename "$dir")-build.log" 2>&1 ) || return 2
}
build "$D/vuln" 0 || { echo "clang -O2 build failed"; exit 2; }
build "$D/fixed" 1 || { echo "clang -O2 fixed build failed"; exit 2; }
[ "$(sha256sum "$D/vuln/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || exit 2
[ "$(sha256sum "$D/fixed/display_ipopt.c" | cut -d' ' -f1)" = "$FIX" ] || exit 2

echo "STAGE baseline"
EXPECT=baseline BIN="$D/vuln/hping3" FILL=0 I0=32 J0=128 \
    RUN_TAG=w11-o2-baseline sh rng-ij-proof.sh > "$D/baseline.out" 2>&1 || {
    tail -20 "$D/baseline.out"; echo "baseline FAILED"; exit 1; }
tail -1 "$D/baseline.out"

echo "STAGE attack"
EXPECT=attack BIN="$D/vuln/hping3" FILL=0 I0=32 J0=128 \
    RUN_TAG=w11-o2-attack sh rng-ij-proof.sh > "$D/attack.out" 2>&1 || {
    tail -20 "$D/attack.out"; echo "attack FAILED"; exit 1; }
tail -1 "$D/attack.out"

echo "STAGE fixed"
EXPECT=fixed BIN="$D/fixed/hping3" FILL=0 I0=32 J0=128 \
    RUN_TAG=w11-o2-fixed sh rng-ij-proof.sh > "$D/fixed.out" 2>&1 || {
    tail -20 "$D/fixed.out"; echo "fixed FAILED"; exit 1; }
tail -1 "$D/fixed.out"

total=$(awk -F'[:, ]+' '/checks run/ {s+=$3} END{print s+0}' \
    "$D/baseline.out" "$D/attack.out" "$D/fixed.out")
echo "REPLAY_IJ_O2_OK: $total checks"
[ "$total" -eq 15 ]
