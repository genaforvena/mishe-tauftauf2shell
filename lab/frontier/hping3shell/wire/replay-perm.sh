#!/bin/sh
# One-command author replay of the permutation RR write experiment.
# Run from anywhere; needs the gitignored pinned source via HPING_SRC.
# Loopback only. Runs a real plain build against crafted RR replies, plus
# a no-inject baseline and a locally patched-build control.
set -eu
cd "$(dirname "$0")"
PINNED=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIXED=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
src=${HPING_SRC:-../provision/hping-src}
[ -f "$src/display_ipopt.c" ] || { echo "HPING_SRC missing: $src"; exit 2; }
[ "$(sha256sum "$src/display_ipopt.c" | cut -d' ' -f1)" = "$PINNED" ] || {
    echo "HPING_SRC display_ipopt.c is not the pinned bytes"; exit 2; }

mkdir -p compat/net evidence
: > compat/net/bpf.h
rm -rf perm-src perm-fixed-src
cp -a "$src" perm-src
( cd perm-src || exit 1
  [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
  make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-perm-build.log 2>&1 )
cp -a perm-src perm-fixed-src
patch -s -o /tmp/w13-perm-fixed.c perm-fixed-src/display_ipopt.c < ../pinned/fix.patch
cp /tmp/w13-perm-fixed.c perm-fixed-src/display_ipopt.c
[ "$(sha256sum perm-fixed-src/display_ipopt.c | cut -d' ' -f1)" = "$FIXED" ] || {
    echo "fix.patch did not produce the expected fixed source"; exit 2; }
( cd perm-fixed-src || exit 1
  make clean >/dev/null 2>&1
  make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-perm-fixed-build.log 2>&1 )

assert() {
    grep -q "^PERM SUMMARY: $1 checks run, PASS$" "$2" || {
        echo "REPLAY_PERM_FAIL: expected $1 PASS in $2"; cat "$2"; exit 1; }
    echo "STAGE OK $3 $1"
}

NO_INJECT=1 BIN=perm-src/hping3 MODE=inc EXPECT=baseline \
    RUN_TAG=perm-baseline sh fullip-proof.sh
assert 3 evidence/fullip-perm-baseline-proof.out baseline

BIN=perm-src/hping3 MODE=dec EXPECT=attack RUN_TAG=perm-attack sh fullip-proof.sh
assert 5 evidence/fullip-perm-attack-proof.out attack-dec

BIN=perm-fixed-src/hping3 MODE=dec EXPECT=fixed RUN_TAG=perm-fixed sh fullip-proof.sh
assert 3 evidence/fullip-perm-fixed-proof.out fixed-dec

echo "REPLAY_PERM_OK: 3 stages"
