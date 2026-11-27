#!/usr/bin/env bash
# W329: no-shim run of the benign-prefix qdatas probe. Private shim-free
# AppRun, the crafted JIF and a full GDB transcript are preserved. Only
# pure GDB reads/watchpoints are used; no register, plugin or heap byte is
# modified by this runner.
# Usage: GIMPJIF_JIF_NAME=w329-benign-280.jif GIMPJIF_LOG_PREFIX=w329-benign-280 \
#        W329_CHANGE=0 GIMPJIF_APPIMAGE_WORK=<tree> bash run-appimage-benign-329.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
GDB_CMD="$HERE/gdb-benign-329.cmd"
PREFIX="${GIMPJIF_LOG_PREFIX:-w329-benign}"
PROBE="$EVID/${PREFIX}-probe.log"
FULL="$EVID/${PREFIX}-full.log"
JIF_NAME="${GIMPJIF_JIF_NAME:-w329-benign-280.jif}"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)

target="$ROOT/AppRun.benign329"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"

file="$EVID/$JIF_NAME"
home="$(mktemp -d /tmp/gimpjif-benign329-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 180 env HOME="$home" \
    W329_LOG="$PROBE" \
    W329_CHANGE="${W329_CHANGE:-0}" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB_CMD --args" \
    ./AppRun.benign329 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$FULL" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

echo "=== W329 probe log ($PROBE) ==="
grep -E 'W329' "$PROBE" | head -120 || true
echo "=== W329 full transcript tail ($FULL) ==="
grep -E 'W329|GIMP-Error|GIMP-Message|fatal error|batch command|Error:' "$FULL" | tail -30 || true
