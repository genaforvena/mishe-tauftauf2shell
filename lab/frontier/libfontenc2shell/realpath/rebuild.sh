#!/bin/sh
# Rebuild the W155 real-library and live-Xvfb replay from upstream sources.
# Run in a clean tree (a git archive of this target works). Requires the
# read-only provisioning clone at $LF2S_SRC (default /tmp/libfontenc-src).
# Refuses to overwrite existing build directories; remove them explicitly if
# a rebuild in the same tree is wanted.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/.." && pwd)
SRC=${LF2S_SRC:-/tmp/libfontenc-src}
PFB=/usr/share/fonts/X11/Type1/NimbusMonoPS-Regular.pfb

for tool in git meson ninja cc Xvfb; do
    command -v "$tool" >/dev/null || { echo "MISSING TOOL $tool" >&2; exit 2; }
done
[ -d "$SRC/.git" ] || { echo "MISSING PROVISIONING CLONE $SRC" >&2; exit 2; }
[ -f "$PFB" ] || { echo "MISSING TYPE1 FONT $PFB" >&2; exit 2; }

# exact upstream revisions: vulnerable parent, fix, and the two release tags
for spec in \
    'vuln 7418fa7a77d1faf795ae40ea92f9ec2828e2a0b9' \
    'fixed 5920c6ee144fffff84b62f5b479171f734f15316' \
    '1.1.9 libfontenc-1.1.9' \
    '1.1.10 libfontenc-1.1.10'
do
    set -- $spec
    variant=$1; rev=$2
    srcdir="$BASE/build-$variant"
    if [ -d "$srcdir" ]; then
        echo "EXISTS $srcdir (remove it to rebuild)"
    else
        mkdir -p "$srcdir"
        echo "ARCHIVE $variant $rev -> $srcdir"
        git -C "$SRC" archive "$rev" | tar -x -C "$srcdir"
    fi
    for mode in plain asan; do
        outdir="$srcdir/out-$mode"
        if [ -f "$outdir/libfontenc.so" ]; then
            echo "LIB EXISTS $variant $mode"
            continue
        fi
        if [ -d "$outdir" ]; then
            echo "INCOMPLETE BUILD DIR $outdir (remove it to rebuild)" >&2
            exit 2
        fi
        if [ "$mode" = asan ]; then
            meson setup "$outdir" "$srcdir" -Db_sanitize=address
        else
            meson setup "$outdir" "$srcdir"
        fi
        # 1.1.10's test-helper target fails on its missing header guard;
        # the library target is the object of this replay in every variant.
        ninja -C "$outdir" libfontenc.so.1.0.0
    done
done

XLIVE="$HERE/xlive"
mkdir -p "$XLIVE/type1fonts" "$XLIVE/logs"
[ -f "$XLIVE/type1fonts/NimbusMonoPS-Regular.pfb" ] ||
    cp "$PFB" "$XLIVE/type1fonts/NimbusMonoPS-Regular.pfb"
printf '1\nNimbusMonoPS-Regular.pfb\n-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-1\n' \
    > "$XLIVE/type1fonts/fonts.dir"
printf '1\ncrafted-1 crafted-1.enc\n' > "$XLIVE/type1fonts/encodings.dir"
cc -O0 -g -Wall "$XLIVE/xfon-load.c" -lX11 -o "$XLIVE/xfon-load"
cc -O0 -g -Wall -shared -fPIC "$XLIVE/fontenc-trace.c" -ldl \
    -o "$XLIVE/fontenc-trace.so"

echo '=== public API matrix ==='
sh "$HERE/run.sh"
echo '=== live Xvfb matrix ==='
sh "$XLIVE/run-live.sh"
