#!/bin/sh
# W17: one crafted X-Trans DNG delivered over a loopback TCP connection to a
# live in-process LibRaw consumer under ASan. Three lanes: vulnerable attack
# (rc 1, ASan WRITE-2 at xtrans_demosaic.cpp:427), vulnerable no-option control
# (rc 0) and patch-derived fixed attack (rc 0). No debugger, no forced call.
set -eu
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)
V_TREE="$ROOT/pinned/LibRaw-0.22.3"
F_TREE="$ROOT/fixed/LibRaw-0.22.3"
INPUT=${1:-"$ROOT/w15/band150.input"}
OUTDIR=${2:-wire-out}

[ -f "$V_TREE/lib/libraw.a" ] || { echo "run bootstrap.sh first"; exit 2; }
[ -f "$F_TREE/lib/libraw.a" ] || { echo "run bootstrap.sh first"; exit 2; }
mkdir -p "$OUTDIR"

build_decoder() { # tree out
    g++ -DLIBRAW_NOTHREADS -O1 -g -I"$1" -w -DUSE_ZLIB \
        -fsanitize=address -fno-omit-frame-pointer \
        -o "$2" wire_decoder.cpp -L"$1/lib" -lraw -lm -lz -fsanitize=address
}
build_decoder "$V_TREE" "$OUTDIR/vuln-decoder"
build_decoder "$F_TREE" "$OUTDIR/fixed-decoder"

export ASAN_OPTIONS=detect_leaks=0
run_lane() { # label binary mode expected-rc
    label=$1; bin=$2; mode=$3; expected=$4
    PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    if [ "$mode" = safe ]; then
        "$bin" "$PORT" safe >"$OUTDIR/$label.out" 2>&1 &
    else
        "$bin" "$PORT" >"$OUTDIR/$label.out" 2>&1 &
    fi
    pid=$!
    python3 send.py "$INPUT" "$PORT" >"$OUTDIR/$label.client" 2>&1
    set +e; wait "$pid"; rc=$?; set -e
    printf '%s rc=%s\n' "$label" "$rc"
    if [ "$rc" = "$expected" ]; then echo "PASS $label-rc"; else echo "FAIL $label-rc want $expected"; fail=1; fi
}

fail=0
run_lane attack "$OUTDIR/vuln-decoder" option 1
run_lane no-option "$OUTDIR/vuln-decoder" safe 0
run_lane fixed "$OUTDIR/fixed-decoder" option 0

check() { if grep -qF "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=1; fi; }
check "$OUTDIR/attack.out" 'RECV bytes=' wire-recv
check "$OUTDIR/attack.out" 'OPEN rc=0' wire-open-ok
check "$OUTDIR/attack.out" 'UNPACK rc=0 w=512 h=512' wire-unpack-ok
check "$OUTDIR/attack.out" 'WRITE of size 2' wire-asan-write2
check "$OUTDIR/attack.out" 'xtrans_demosaic.cpp:427' wire-asan-site
if grep -q 'WRITE of size 2' "$OUTDIR/no-option.out" || grep -q 'WRITE of size 2' "$OUTDIR/fixed.out"; then
    echo 'FAIL controls-clean'; fail=1
else
    echo 'PASS controls-clean'
fi
if [ "$fail" = 0 ]; then echo WIRE_OOB_OK; else echo WIRE_OOB_FAIL; fi
exit "$fail"
