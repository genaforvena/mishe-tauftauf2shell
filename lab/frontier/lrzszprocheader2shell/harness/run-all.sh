#!/bin/sh
# Replay the four pinned arms from a clean checkout of the staging commit.
# Provisioning from public GitHub and the host gettext package is allowed;
# no external target is contacted. All runs are local files/loopback only.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
VULN=b1fc8a01e3a074f8462a29dca45ed7c8fd2ef665
FIXED=b18b579272fa94748388364014f22e20712288d4
SAN="-fsanitize=address -fno-omit-frame-pointer -g -O1"

provision() {
  d=$1; rev=$2; extra=$3
  if [ ! -d "$d" ]; then
    if [ ! -d src/.git ]; then git clone -q https://github.com/UweOhse/lrzsz.git src; fi
    git -C src worktree add -q "../$d" "$rev"
  fi
  (cd "$d" || exit 1
   sed -i 's/AC_PREREQ(\[2\.72\])/AC_PREREQ([2.71])/' configure.ac
   cp /usr/share/gettext/config.rpath config.rpath
   cp /usr/share/gettext/po/Makefile.in.in po/Makefile.in.in
   chmod +x config.rpath
   AUTOPOINT=true autoreconf -fi > autoreconf.log 2>&1
   ./configure CFLAGS="$SAN $extra" LDFLAGS="-fsanitize=address" > configure.log 2>&1
   make -j4 > build.log 2>&1 || true
  )
}

provision vuln "$VULN" ""
provision fixed "$FIXED" "-Wno-error"
mkdir -p evidence

build_harness() {
  name=$1; tree=$2; shift 2
  objs=$(ls "$tree"/src/*.o 2>/dev/null | grep -vE '/(lrz|lsz|linesimulator|timestamp|zmodemfuzz|zmodemsnif)\.o$' | tr '\n' ' ')
  cc $SAN -Wno-error -DHAVE_CONFIG_H -DNFGVMIN \
    -DLOCALEDIR='"/usr/local/share/locale"' \
    -I "$tree" -I "$tree/src" -I vuln/lib -I vuln/src \
    harness/procheader-harness.c $objs vuln/lib/libzmodem.a -o "evidence/$name"
}
build_harness harness-vuln vuln
build_harness harness-fixed fixed

pass=0; fail=0
check() {
  label=$1; bin=$2; len=$3; fill=$4; expect=$5
  set +e
  ASAN_OPTIONS=detect_leaks=0 "evidence/$bin" "$len" "$fill" > "evidence/$label.out" 2>&1
  rc=$?
  set -e
  grep -q "$expect" "evidence/$label.out" && ok=1 || ok=0
  if [ "$expect" = "NO_ASAN" ]; then
    grep -q 'ERROR: AddressSanitizer' "evidence/$label.out" && ok=0
  fi
  if [ "$ok" = 1 ]; then pass=$((pass+1)); echo "PASS $label rc=$rc";
  else fail=$((fail+1)); echo "FAIL $label rc=$rc"; fi
}
check vuln-safe   harness-vuln  16    67 'Pathname_len=16'
check vuln-attack harness-vuln  12000 67 'WRITE of size 12001'
check fixed-attack harness-fixed 12000 67 'Pathname_len=12000'
check fixed-safe  harness-fixed 16    67 'Pathname_len=16'

if grep -q 'ERROR: AddressSanitizer' evidence/fixed-attack.out || grep -q 'ERROR: AddressSanitizer' evidence/fixed-safe.out; then
  echo 'FAIL fixed-arm ASan'; fail=$((fail+1));
else
  pass=$((pass+1)); echo 'PASS fixed-arms no ASan';
fi
echo "RUN_ALL_OK $pass PASS / $fail FAIL"
[ "$fail" = 0 ]
