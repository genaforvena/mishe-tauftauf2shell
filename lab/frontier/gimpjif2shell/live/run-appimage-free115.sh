#!/usr/bin/env bash
# W335: one bounded no-shim GDB replay of the published 8 KiB JIF to capture
# the freed chunk's size word and the heap-info address free+115 dereferences.
# Ceiling: allocator dereference attempt on corrupt metadata, NOT a chosen
# address write, marker, or command.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
OUT="${GIMPJIF_W335_OUT:-$EVID/w335-free115.log}"
mkdir -p "$WORK" "$EVID"
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ] || [ ! -x "$ROOT/AppRun" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)

JIF="$EVID/gdb-8192.jif"
if [ ! -f "$JIF" ]; then
  python3 "$BASE/realglib/make-jif.py" "$JIF" published-run 8192 4d > /dev/null
fi
sha256sum "$JIF"

home="$(mktemp -d /tmp/gimpjif-free115-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 150 env HOME="$home" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-free115.cmd --args" \
    ./AppRun -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$JIF\" \"gdb-8192.jif\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$OUT" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

grep -q 'W335 PLUGIN SIGNAL' "$OUT" && echo "PASS: fault captured" || echo "FAIL: no fault captured"
grep -E 'W335 freed_user|size_word|heapinfo|^\$?[0-9a-f]+:|^rax|^rdx' "$OUT" | head -30
sha256sum "$OUT"
