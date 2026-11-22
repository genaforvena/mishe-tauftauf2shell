#!/usr/bin/env bash
# Local-only replay of the CVE-2026-85495 real-daemon PTY experiment.
# Requires sudo -n (pppd needs root) and the ppp_async kernel line discipline.
set -euo pipefail
cd "$(dirname "$0")"

PINS=../pins
RAW=raw
mkdir -p "$RAW"
sudo -n rm -f "$RAW"/w122-*-asan.*
sha256sum -c <<'EOF'
96f962b9f9411ee4a75da34e5b6177eaec4dce0527af009891210641e0b74edf  ../pins/ppp-2.5.3.tar.gz
379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31  ../pins/ppp-2.5.4.tar.gz
8593bced5e3722c53a63922760fc760f59d18072544fae9d0f4046ba036ffaad  ../pins/fix-cc8b00c.patch
4fa8b23ad1238a981215c8d9b312d92458146b047d92ca9601e6d81c5a42ac58  ../pins/fix-1baf2ac.patch
EOF

CFLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer'
build_vuln() {
    rm -rf "$RAW/build-vuln"
    tar xzf "$PINS/ppp-2.5.3.tar.gz" -C "$RAW"
    mv "$RAW/ppp-project-ppp-0cfdb73" "$RAW/build-vuln"
    (cd "$RAW/build-vuln" && ./autogen.sh >/dev/null 2>&1 &&
     ./configure CC=gcc CFLAGS="$CFLAGS" LDFLAGS=-fsanitize=address \
        >configure.log 2>&1 &&
     make -C pppd -j4 pppd >build.log 2>&1)
}

build_fixed() {
    rm -rf "$RAW/build-fixed"
    tar xzf "$PINS/ppp-2.5.4.tar.gz" -C "$RAW"
    mv "$RAW/ppp-2.5.4" "$RAW/build-fixed"
    (cd "$RAW/build-fixed" &&
     ./configure CC=gcc CFLAGS="$CFLAGS" LDFLAGS=-fsanitize=address \
        >configure.log 2>&1 &&
     make -C pppd -j4 pppd >build.log 2>&1)
}

[ -x "$RAW/build-vuln/pppd/pppd" ] || build_vuln
[ -x "$RAW/build-fixed/pppd/pppd" ] || build_fixed
V="$PWD/$RAW/build-vuln/pppd/pppd"
F="$PWD/$RAW/build-fixed/pppd/pppd"

sudo -n modprobe ppp_async

python3 pty_driver.py --binary "$V" --n 3 --tag w122-vuln-n3f
python3 pty_driver.py --binary "$V" --n 301 --tag w122-vuln-n301
python3 pty_driver.py --binary "$V" --n 374 --tag w122-vuln-n374
python3 pty_driver.py --binary "$V" --n 300 --tag w122-vuln-n300
python3 pty_driver.py --binary "$F" --n 301 --tag w122-fixed-n301b
python3 pty_driver.py --binary "$F" --n 3 --tag w122-fixed-n3b

python3 normalize.py
