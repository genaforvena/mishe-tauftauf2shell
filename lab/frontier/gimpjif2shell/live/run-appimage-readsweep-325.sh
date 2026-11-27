#!/usr/bin/env bash
# W325: no-shim post-inflate read-watch sweep against the real GIMP 3.2.8
# file-gif-load plug-in. SHA-verified AppImage, shim-free private AppRun,
# the already-committed 1024-byte JIF, and a full GDB transcript are kept.
# The debugger only reads memory and watches addresses; it writes no
# register, heap byte or plugin byte.
# Usage: GIMPJIF_APPIMAGE_WORK=<tree> bash run-appimage-readsweep-325.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
GDB_CMD="$HERE/gdb-readsweep-325.cmd"
PREFIX="${GIMPJIF_LOG_PREFIX:-w325-readsweep}"
PROBE="$EVID/${PREFIX}-probe.log"
FULL="$EVID/${PREFIX}-full.log"
JIF="$EVID/span-1024.jif"
SECS="${GIMPJIF_TIMEOUT_SECS:-150}"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
[ -f "$GDB_CMD" ] && [ -f "$JIF" ]

# Regenerate a private AppRun with every gimpjif2shell shim line deleted.
target="$ROOT/AppRun.readsweep325"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"

home="$(mktemp -d /tmp/gimpjif-readsweep-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 "$SECS" env HOME="$home" \
    W325_LOG="$PROBE" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB_CMD --args" \
    ./AppRun.readsweep325 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$JIF\" \"$(basename "$JIF")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$FULL" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

echo "=== W325 probe log ($PROBE) ==="
grep -E 'W325' "$PROBE" | head -160 || true
echo "=== W325 full transcript tail ($FULL) ==="
grep -E 'W325|GIMP-Error|fatal error|batch command|Heap corruption' "$FULL" | tail -40 || true
