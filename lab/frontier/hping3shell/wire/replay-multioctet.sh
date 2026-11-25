#!/bin/sh
# One-command author replay of three chosen destination octets under
# --rand-dest 127.x.x.x.  Rebuilds vulnerable and locally patched clang -O0
# trees from the provisioned pinned source.  All probes stay on 127/8 on lo;
# GDB only reads live state.
set -u
cd "$(dirname "$0")" || exit 1
PATCH=$PWD/../pinned/fix.patch
SRC=${HPING_SRC:-../provision/hping-src}
PIN=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
FILL=${MULTI_FILL:-1}
[ -f "$SRC/display_ipopt.c" ] || { echo "HPING_SRC missing: $SRC"; exit 2; }
[ "$(sha256sum "$SRC/display_ipopt.c" | cut -d' ' -f1)" = "$PIN" ] || {
    echo "provisioned source is not the pinned bytes"; exit 2; }

D=evidence/w16-multioctet
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
    # rng-ij-proof.sh still runs check_ij.py, whose predictor hardcodes a
    # single wildcard octet; on 127.x.x.x that stage is inapplicable.  The
    # full-address checker below is authoritative for this template.
    EXPECT=$expect BIN=$bin TARGET_TEMPLATE=127.x.x.x FILL=$FILL I0=32 J0=16 \
        RUN_TAG="w16-replay-$label" sh rng-ij-proof.sh > "$D/$label.out" 2>&1
    echo "legacy check_ij driver rc=$? (inapplicable predictor)"
    python3 check_multioctet.py "evidence/ij-w16-replay-$label-gdb.out" \
        "evidence/ij-w16-replay-$label-run.out" --fill "$FILL" --wildcards 3 \
        --expect "$expect" > "$D/$label-check.out" 2>&1 || {
        cat "$D/$label-check.out"; echo "$label check FAILED"; exit 1; }
    cat "$D/$label-check.out"
}

run_stage baseline baseline "$D/vuln/hping3"
run_stage attack attack "$D/vuln/hping3"
run_stage fixed fixed "$D/fixed/hping3"

total=$(awk -F'[:, ]+' '/MULTI SUMMARY/ {s+=$3} END{print s+0}' \
    "$D/baseline-check.out" "$D/attack-check.out" "$D/fixed-check.out")
echo "REPLAY_MULTIOCTET_OK: $total checks, fill=0x$(printf '%02x' "$FILL")"
[ "$total" -eq 12 ]
