#!/usr/bin/env bash
# W361: shim-free live runner on the larger wrapped geometry
# (38020x56483, len*height=0x8000000c, data_size=0x18). Structurally the
# W340 runner with a different PRE bound and W361 env names. It strips every
# gimpjif2shell preload line, re-verifies the AppImage and drives gimp-file-load
# under a read-only GDB observer. No target memory or register is written.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
APPRUN="$ROOT/AppRun.w361"
EVID="$HERE/evidence"
JIF="${GIMPJIF_W361_JIF:?set GIMPJIF_W361_JIF to an absolute 101-char JIF path}"
OUT="${GIMPJIF_W361_OUT:?set GIMPJIF_W361_OUT to a private log path}"
LOG="${GIMPJIF_W361_LOG:-/tmp/w361-$$.log}"
GDB="${GIMPJIF_W361_GDB:-$HERE/gdb-w361-layout.cmd}"
AVAIL="${GIMPJIF_W361_AVAIL:-2147483660}"       # 0x8000000c
mkdir -p "$(dirname "$OUT")" "$EVID"
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ] || [ ! -x "$ROOT/AppRun" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
[ -f "$JIF" ] || { echo "missing $JIF" >&2; exit 1; }
sha256sum "$JIF" "$GDB"
# Remove every target preload; the default AppRun preloads patch-shim.so.
: > "$APPRUN"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$APPRUN"
done < "$ROOT/AppRun"
chmod +x "$APPRUN"
! grep -q 'gimpjif2shell/live/.*shim.so' "$APPRUN"

home="$(mktemp -d /tmp/gimpjif-w361-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 150 env HOME="$home" \
    W337_LOG="$LOG" W361_AVAIL="$AVAIL" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB --args" \
    ./AppRun.w361 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$JIF\" \"$(basename "$JIF")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$OUT" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

grep -q 'W361 PRE avail=0x8000000c' "$LOG" && echo "PASS: pinned inflate reached" || echo "FAIL: no pinned inflate"
grep -q 'W361 SIGNAL' "$LOG" && echo "PASS: fault captured in GDB" || echo "INFO: no in-GDB fault stop"
cat "$LOG" 2>/dev/null || true
echo "--- tail ---"
grep -E 'W361 |Plug-in crashed|Fatal signal' "$OUT" "$LOG" | tail -40
