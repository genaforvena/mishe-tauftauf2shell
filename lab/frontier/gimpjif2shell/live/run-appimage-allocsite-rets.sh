#!/usr/bin/env bash
# W321: no-shim run of the validated malloc-return tracer against the
# SHA-verified GIMP 3.2.8 AppImage. Regenerates a private shim-free AppRun,
# uses the same published 8 KiB JIF as W317/W320, and preserves the full
# GDB log. Nothing is patched: no LD_PRELOAD, no plugin byte, no heap byte.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
mkdir -p "$EVID"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
target="$ROOT/AppRun.rets"
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
home="$(mktemp -d /tmp/gimpjif-rets-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 120 env HOME="$home" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-allocsite-rets.cmd --args" \
    ./AppRun.rets -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$EVID/w321-allocsite-rets.log" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true
grep -E 'W321|Breakpoint|GIMP-Error|fatal error' "$EVID/w321-allocsite-rets.log" | head -60 || true
