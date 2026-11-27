#!/usr/bin/env bash
# W324: no-shim run of the partial-qdatas-overwrite probe. Private shim-free
# AppRun, the crafted 282-byte JIF, and a full GDB transcript are preserved.
# Only pure GDB reads/watchpoints are used; no register, plugin or heap byte
# is modified by this runner.
# Usage: GIMPJIF_APPIMAGE_WORK=<tree> bash run-appimage-partialptr-324.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
GDB_CMD="$HERE/gdb-partialptr-324.cmd"
PREFIX="${GIMPJIF_LOG_PREFIX:-w324-partialptr}"
PROBE="$EVID/${PREFIX}-probe.log"
FULL="$EVID/${PREFIX}-full.log"
JIF_NAME="${GIMPJIF_JIF_NAME:-w324-partial-4140.jif}"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)

# Regenerate a private AppRun with every gimpjif2shell shim line deleted.
target="$ROOT/AppRun.partialptr324"
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
home="$(mktemp -d /tmp/gimpjif-partialptr-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 180 env HOME="$home" \
    W324_LOG="$PROBE" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB_CMD --args" \
    ./AppRun.partialptr324 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$FULL" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

echo "=== W324 probe log ($PROBE) ==="
grep -E 'W324' "$PROBE" | head -120 || true
echo "=== W324 full transcript tail ($FULL) ==="
grep -E 'W324|GIMP-Error|fatal error|batch command' "$FULL" | tail -30 || true
