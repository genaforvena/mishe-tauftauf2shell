#!/bin/sh
# W183 live-object pointer control at the real-library public API.
# Requires the build-* trees provisioned by realpath/rebuild.sh.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../../.." && pwd)
REAL="$BASE/realpath"
OUT="$HERE"
TMP="$REAL/tmp/ptrctrl"
mkdir -p "$TMP/crafted" "$TMP/safe"
printf '1\nheapobj crafted.enc\n' > "$TMP/crafted/encodings.dir"
printf '1\nsafe safe.enc\n' > "$TMP/safe/encodings.dir"
cp "$HERE/crafted.enc" "$TMP/crafted/crafted.enc"
cp "$HERE/safe.enc" "$TMP/safe/safe.enc"

for spec in 'vuln plain out-plain' 'vuln asan out-asan' 'fixed plain out-plain'; do
    set -- $spec
    variant=$1; mode=$2; outdir=$3
    libdir="$BASE/build-$variant/$outdir"
    [ -f "$libdir/libfontenc.so" ] || { echo "MISSING LIB $variant $mode" >&2; exit 2; }
    extra=""
    [ "$mode" = asan ] && extra="-fsanitize=address"
    cc -O0 -g -Wall $extra -I"$BASE/build-$variant/include" \
        "$HERE/probe.c" -L"$libdir" -Wl,-rpath,"$libdir" \
        -lfontenc -o "$TMP/probe-$variant-$mode"
done

run_case() {
    tag=$1; bin=$2; charset=$3; dir=$4; shift 4
    rc=0
    MALLOC_MMAP_THRESHOLD_=262144 \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    FONT_ENCODINGS_DIRECTORY="$dir" \
    timeout 30 setarch x86_64 -R "$bin" "$charset" "$dir/dummy.pcf" \
        > "$OUT/$tag.txt" 2>&1 || rc=$?
    printf '\nRC=%s\n' "$rc" >> "$OUT/$tag.txt"
    printf '%s rc=%s\n' "$tag" "$rc"
}

run_case vuln-crafted "$TMP/probe-vuln-plain" heapobj "$TMP/crafted"
run_case vuln-safe "$TMP/probe-vuln-plain" safe "$TMP/safe"
run_case fixed-crafted "$TMP/probe-fixed-plain" heapobj "$TMP/crafted"
run_case vuln-asan-crafted "$TMP/probe-vuln-asan" heapobj "$TMP/crafted"
