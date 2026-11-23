#!/bin/sh
# Replay the committed aarch64 cases under qemu-user and check the expected
# outcomes. Run from lab/openexr2shell-real after build-cross.sh for both tags.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SYS="$LAB/aarch64/sysroot/usr/lib/aarch64-linux-gnu"
export LD_LIBRARY_PATH="$SYS"
Q="qemu-aarch64-static -L /usr/aarch64-linux-gnu"
PASS=0
FAIL=0

check() {
  name=$1; want_rc=$2; want=$3; shift 3
  out="$LAB/aarch64/evidence/replay-$name.out"
  # shellcheck disable=SC2086
  $Q "$@" >"$out" 2>&1
  rc=$?
  if [ "$rc" -eq "$want_rc" ] && grep -q "$want" "$out"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL $name rc=$rc want_rc=$want_rc want='$want'"
    head -12 "$out"
  fi
}

cd "$LAB" || exit 1
check flat-vuln-baseline  0 'DECODE rv=0'          aarch64/flat_harness-vuln cases/baseline.exr
check flat-vuln-poc     134 'free(): invalid pointer' aarch64/flat_harness-vuln cases/poc.exr
check flat-fixed-poc      1 'DECODE rv=23'         aarch64/flat_harness-fixed cases/poc.exr
check flat-fixed-baseline 0 'DECODE rv=0'          aarch64/flat_harness-fixed cases/baseline.exr
check guard-vuln-baseline 0 'GUARD-TOTAL post-decode changed=0' aarch64/guarded_harness-vuln cases/baseline.exr
check guard-vuln-poc      0 'GUARD-CHANGE alloc=23 size=64 changed=4032 first=+0 expected=0xa1 actual@first=0x57' aarch64/guarded_harness-vuln cases/poc.exr
check guard-fixed-poc     0 'GUARD-TOTAL post-decode changed=0' aarch64/guarded_harness-fixed cases/poc.exr
check tiled-vuln-baseline 0 'DECODE rv=0'          aarch64/tiled_harness-vuln cases/baseline_tiled.exr
check tiled-vuln-poc    134 'free(): invalid pointer' aarch64/tiled_harness-vuln cases/poc_tiled.exr
check tiled-fixed-poc     1 'DECODE rv=23'         aarch64/tiled_harness-fixed cases/poc_tiled.exr

echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
