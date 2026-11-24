#!/bin/sh
# W172: replay the committed W164 deep-tiled claims from a clean checkout.
# Needs the three harness build trees (build-vuln-plain, build-vuln-asan,
# build-fixed-asan) from harness/build.sh; regenerates both tiled EXRs.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB" || exit 1
PASS=0
FAIL=0

check_hash() {
  want=$1; file=$2
  got=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL hash $file got=$got want=$want"
  fi
}

check() {
  name=$1; want_rc=$2; want=$3; shift 3
  out="evidence/replay-$name.out"
  "$@" >"$out" 2>&1
  rc=$?
  if [ "$rc" -eq "$want_rc" ] && grep -qF "$want" "$out"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL $name rc=$rc want_rc=$want_rc want='$want'"
    head -12 "$out"
  fi
}

./bin-vuln-asan/gen_baseline_tiled cases/baseline_tiled.exr >/dev/null
python3 cases/make_poc_tiled.py cases/baseline_tiled.exr cases/poc_tiled.exr >/dev/null
check_hash 6a7a76a6789d35ad826a61a5d877632ebdb7c42130cc2d7698a2ca2f979af49e cases/baseline_tiled.exr
check_hash aa9dba1f009d80a8accecea6531ebfcd4c15f2fe6e2cad0b4ec4df6d92a41ccc cases/poc_tiled.exr

check vp-tiled-baseline  0 'DECODE rv=0'             ./bin-vuln-plain/tiled_harness cases/baseline_tiled.exr
check vp-tiled-poc     134 'free(): invalid pointer'  ./bin-vuln-plain/tiled_harness cases/poc_tiled.exr
check va-tiled-baseline  0 'DECODE rv=0'             ./bin-vuln-asan/tiled_harness cases/baseline_tiled.exr
check va-tiled-poc       1 'memcpy-param-overlap'     ./bin-vuln-asan/tiled_harness cases/poc_tiled.exr
check fa-tiled-poc       1 'DECODE rv=23'            ./bin-fixed-asan/tiled_harness cases/poc_tiled.exr
check guard-tiled-base   0 'GUARD-TOTAL post-decode changed=0' ./bin-vuln-plain/guarded_harness cases/baseline_tiled.exr tile
check guard-tiled-poc    0 'changed=4032 first=+0'   ./bin-vuln-plain/guarded_harness cases/poc_tiled.exr tile
check guard-scan-regress 0 'changed=4032 first=+0'   ./bin-vuln-plain/guarded_harness cases/poc.exr

echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
