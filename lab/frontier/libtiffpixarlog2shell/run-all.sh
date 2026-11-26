#!/usr/bin/env bash
# Re-run the pinned CVE-2026-12912 PixarLog ASan reproduction from clean
# sources if necessary. Prints RESULT PASS=<n> FAIL=<m>.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT" || exit 1
mkdir -p src work runs

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1
export LD_LIBRARY_PATH="$ROOT/src/tiff-4.7.1/libtiff/.libs:$ROOT/src/tiff-4.7.2/libtiff/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

PASS=0
FAIL=0
check()
{
    desc=$1
    cmd=$2
    if eval "$cmd" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        printf 'PASS %s\n' "$desc"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s\n' "$desc"
    fi
}

LIBS='-lwebp -lzstd -llzma -lLerc -ljbig -ljpeg -ldeflate -lz -lm'
ensure_source()
{
    ver=$1
    if [ ! -d "src/tiff-$ver" ]; then
        tar xzf "pins/tiff-$ver.tar.gz" -C src || return 1
    fi
}
ensure_build()
{
    ver=$1
    ensure_source "$ver" || return 1
    if [ ! -f "src/tiff-$ver/libtiff/.libs/libtiff.a" ]; then
        (cd "src/tiff-$ver" &&
            CFLAGS='-fsanitize=address -g -O0' \
            LDFLAGS='-fsanitize=address' \
            ./configure --disable-shared > "$ROOT/config-$ver.log" 2>&1 &&
            make -j4 > "$ROOT/build-$ver.log" 2>&1) || return 1
    fi
}
link_harness()
{
    ver=$1
    gcc -fsanitize=address -g -O0 \
        -I "src/tiff-$ver/libtiff" -I "src/tiff-$ver" \
        harness.c "src/tiff-$ver/libtiff/.libs/libtiff.a" $LIBS \
        -o "harness-$ver"
}

check 'SHA-256 pins (tarballs, patch, issue page, harness)' \
    'sha256sum -c pins/PIN_HASHES.txt'
for ver in 4.7.1 4.7.2; do
    check "ASan libtiff build $ver" "ensure_build $ver"
    check "harness link $ver" "link_harness $ver"
done
if [ "$FAIL" -ne 0 ]; then
    printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
    exit 1
fi

run_case()
{
    name=$1
    ver=$2
    mode=$3
    ./"harness-$ver" "$mode" "work/$name.tif" > "runs/$name.log" 2>&1
    echo "$?" > "runs/$name.rc"
}

run_case attack-471        4.7.1 abgr3
run_case fixed-472         4.7.2 abgr3
run_case control-rgb-471   4.7.1 rgb3
run_case control-stride4-471 4.7.1 abgr4
run_case control-rgb-472   4.7.2 rgb3

check 'attack 4.7.1 abgr3 aborts under ASan' \
    'grep -qx 1 runs/attack-471.rc'
check 'attack WRITE of size 1' \
    'grep -qF "WRITE of size 1" runs/attack-471.log'
check 'attack writes 0 bytes after 192-byte region' \
    'grep -qF "0 bytes after 192-byte region" runs/attack-471.log'
check 'attack reports horizontalAccumulate8abgr at tif_pixarlog.c:470' \
    'grep -qF "horizontalAccumulate8abgr" runs/attack-471.log && grep -qF "tif_pixarlog.c:470" runs/attack-471.log'
check 'attack reports PixarLogDecode at tif_pixarlog.c:979' \
    'grep -qF "PixarLogDecode /" runs/attack-471.log && grep -qF "tif_pixarlog.c:979" runs/attack-471.log'
check 'attack reports TIFFReadScanline at tif_read.c:465' \
    'grep -qF "TIFFReadScanline /" runs/attack-471.log && grep -qF "tif_read.c:465" runs/attack-471.log'
check 'attack caller stack reaches harness TIFFReadScanline (harness.c:124)' \
    'grep -qF "harness.c:124" runs/attack-471.log'
check 'attack allocation stack points to harness malloc (harness.c:115)' \
    'grep -qF "harness.c:115" runs/attack-471.log'
check 'fixed 4.7.2 abgr3 completes without ASan abort' \
    'grep -qx 0 runs/fixed-472.rc'
check 'fixed 4.7.2 rejects decode (TIFF_READ_SCANLINE_RC=-1)' \
    'grep -qF "TIFF_READ_SCANLINE_RC=-1" runs/fixed-472.log'
check 'fixed 4.7.2 emits ABGR output-buffer guard error' \
    'grep -qF "PixarLogDecode: Output buffer too small for PixarLog ABGR data." runs/fixed-472.log'
check 'fixed 4.7.2 log has no AddressSanitizer report' \
    '! grep -qF AddressSanitizer runs/fixed-472.log'

for name in control-rgb-471 control-stride4-471 control-rgb-472; do
    check "$name completes without ASan abort" "grep -qx 0 runs/$name.rc"
    check "$name decodes successfully (TIFF_READ_SCANLINE_RC=1)" \
        "grep -qF 'TIFF_READ_SCANLINE_RC=1' runs/$name.log"
    check "$name log has no AddressSanitizer report" \
        "! grep -qF AddressSanitizer runs/$name.log"
done

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
