#!/usr/bin/env bash
# W322: no-shim run of the GType-naming probe. Private shim-free AppRun,
# the same 8 KiB JIF, full GDB log preserved. Only pure GLib lookups are
# called in the inferior; no plugin or heap byte is modified by this runner.
# Usage: GIMPJIF_GDB_CMD=<script> GIMPJIF_LOG_NAME=<file> bash run-appimage-typenode-322.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
GDB_CMD="${GIMPJIF_GDB_CMD:-$HERE/gdb-typenode-322.cmd}"
LOG_NAME="${GIMPJIF_LOG_NAME:-w322-typenode.log}"
mkdir -p "$EVID"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
target="$ROOT/AppRun.typenode322"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"
file="$HERE/evidence/gdb-liveptr-8192.jif"
home="$(mktemp -d /tmp/gimpjif-typenode-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 180 env HOME="$home" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB_CMD --args" \
    ./AppRun.typenode322 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$EVID/$LOG_NAME" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true
grep -E 'W322|Breakpoint|GIMP-Error|fatal error' "$EVID/$LOG_NAME" | head -60 || true
