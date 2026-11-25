#!/bin/sh
# One-command author replay of three DISTINCT chosen destination octets.
# Rebuilds vulnerable and locally patched clang -O0 trees from the pinned
# source, rechecks both hashes, runs baseline / attack / patched stages.
# All probes stay inside 127/8 on lo; GDB only reads live state.
set -u
cd "$(dirname "$0")" || exit 1
PATCH=$PWD/../pinned/fix.patch
SRC=${HPING_SRC:-../provision/hping-src}
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
PATTERN=${PATTERN:-patterns/w17-three-distinct.hex}
[ -f "$SRC/display_ipopt.c" ] || { echo "HPING_SRC missing: $SRC"; exit 2; }
[ "$(sha256sum "$SRC/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || {
    echo "provisioned source is not the pinned bytes"; exit 2; }

D=evidence/w17-pattern
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
      make -j4 CC=clang CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
          >"../$(basename "$dir")-build.log" 2>&1 ) || return 2
}
build "$D/vuln" 0 || { echo "clang -O0 build failed"; exit 2; }
build "$D/fixed" 1 || { echo "clang -O0 fixed build failed"; exit 2; }
[ "$(sha256sum "$D/vuln/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || exit 2
[ "$(sha256sum "$D/fixed/display_ipopt.c" | cut -d' ' -f1)" = "$FIX" ] || exit 2

run_stage() {
    label=$1; expect=$2; bin=$3
    EXPECT=$expect BIN=$bin RUN_TAG="w17-replay-$label" PATTERN=$PATTERN \
        sh rng-pattern-proof.sh > "$D/$label.out" 2>&1
    rc=$?
    cat "evidence/pt-w17-replay-$label-proof.out" 2>/dev/null
    echo "STAGE $label rc=$rc"
    [ "$rc" -eq 0 ] || exit 1
}
run_stage baseline baseline "$D/vuln/hping3"
run_stage attack attack "$D/vuln/hping3"
run_stage fixed fixed "$D/fixed/hping3"
echo "REPLAY_PATTERN_OK: 3 stages, $PATTERN"
