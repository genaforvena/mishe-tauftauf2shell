#!/usr/bin/env bash
# W314: rebuild the real file-gif-load plug-in from pinned GIMP 3.2.8 source
# with and without the pinned fix commit, then run the same safe and attack
# JIFs in two private copies of the SHA-verified AppImage runtime.
# No shim, no gdb, no plugin byte patched in memory: the only difference is
# the pinned source patch. Temporary build roots stay outside the repo.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
SRC_URL='https://download.gimp.org/gimp/v3.2/gimp-3.2.8.tar.xz'
SRC_SHA='16a2696cadc9e03a2ef97ccb895e062f654cb2b8211fb57074db85f26646c847'
FIX_URL='https://gitlab.gnome.org/GNOME/gimp/-/commit/2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7.patch'
FIX_SHA='92ca1593776352c11e477cfb0307874bae22de240842e893d861085c9f5edd43'
PLUGREL='usr/lib/x86_64-linux-gnu/gimp/3.0/plug-ins/file-gif-load/file-gif-load'
BUILD="$(mktemp -d /tmp/gimpjif-fixedctl-build-XXXXXX)"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check () { if "$@"; then ok "$*"; else no "$*"; fi; }

mkdir -p "$EVID"
[ -f "$IMG" ] && [ -f "$WORK/SHA256SUMS" ] || {
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first" >&2; exit 1; }
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
[ -x "$ROOT/AppRun" ] || {
  chmod +x "$IMG"; (cd "$WORK" && ./"$IMG" --appimage-extract >/dev/null); }
"$ROOT/AppRun" --version | grep -q '3.2.8'
ok "official GIMP 3.2.8 runtime verified"

curl -fsSL --max-time 180 -o "$BUILD/gimp.tar.xz" "$SRC_URL"
echo "$SRC_SHA  $BUILD/gimp.tar.xz" | sha256sum -c -
curl -fsSL --max-time 30 -o "$BUILD/fix.patch" "$FIX_URL"
echo "$FIX_SHA  $BUILD/fix.patch" | sha256sum -c -
tar -xf "$BUILD/gimp.tar.xz" -C "$BUILD"
SRC="$BUILD/gimp-3.2.8"
mkdir -p "$BUILD/gen"
cat > "$BUILD/gen/config.h" <<'CFG'
#define GIMP_VERSION "3.2.8"
#define PACKAGE "gimp"
#define GETTEXT_PACKAGE "gimp30"
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
CFG
INCS=''
for d in "$ROOT"/usr/include/*; do [ -d "$d" ] && INCS="$INCS -I$d"; done
INCS="-I$ROOT/usr/include/gimp-3.0 -I$ROOT/usr/include -I$BUILD/gen -I$SRC -I$SRC/libgimp $INCS"
CFLAGS="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 zlib)"
LIBS="-L$ROOT/usr/lib/x86_64-linux-gnu -Wl,-rpath,$ROOT/usr/lib/x86_64-linux-gnu -lgimp-3.0 -lgimpbase-3.0 -lgimpcolor-3.0 -lgimpconfig-3.0 -lgimpmath-3.0 -lgegl-0.4 -lbabl-0.1 $(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 zlib)"

build_plugin () {
  gcc -fPIE -pie -g -O0 \
    -Wl,--dynamic-linker,./usr/lib64/ld-linux-x86-64.so.2 \
    -o "$1" $INCS $CFLAGS "$SRC/plug-ins/common/file-gif-load.c" $LIBS
}

build_plugin "$BUILD/vuln"                                  # pristine 3.2.8
(cd "$SRC" && patch -p1 < "$BUILD/fix.patch" >/dev/null)
build_plugin "$BUILD/fixed"                                 # same source + fix
(cd "$SRC" && patch -R -p1 < "$BUILD/fix.patch" >/dev/null)
sha256sum "$BUILD/vuln" "$BUILD/fixed" > "$EVID/fixedctl-binaries.sha256"
! cmp -s "$BUILD/vuln" "$BUILD/fixed"
ok "vulnerable and fixed plug-in binaries differ"

for v in vuln fixed; do
  rm -rf "$BUILD/root-$v"
  cp -al "$ROOT" "$BUILD/root-$v"
  rm -f "$BUILD/root-$v/$PLUGREL"
  cp "$BUILD/$v" "$BUILD/root-$v/$PLUGREL"
  chmod 755 "$BUILD/root-$v/$PLUGREL"
  : > "$BUILD/root-$v/AppRun.noshim"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *gimpjif2shell/live/*shim.so*) continue ;;
    esac
    printf '%s\n' "$line" >> "$BUILD/root-$v/AppRun.noshim"
  done < "$BUILD/root-$v/AppRun"
  chmod +x "$BUILD/root-$v/AppRun.noshim"
done
! grep -q 'gimpjif2shell/live/.*shim.so' "$BUILD/root-vuln/AppRun.noshim"
! grep -q 'gimpjif2shell/live/.*shim.so' "$BUILD/root-fixed/AppRun.noshim"
ok "no-shim AppRun regenerated in both private roots"
ok "two private AppImage roots hold the rebuilt plug-ins"

run_case () {
  local v="$1"
  local kind="$2"
  local jif="$3"
  local out="$EVID/fixedctl-$v-$kind.log"
  local home; home="$(mktemp -d /tmp/gimpjif-fixedctlhome-XXXXXX)"
  (cd "$BUILD/root-$v" && exec setsid timeout -k 5 90 env HOME="$home" \
      ./AppRun.noshim -i --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$jif\" \"$(basename "$jif")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  local pid=$! rc=0
  wait "$pid" || rc=$?
  kill -9 -- "-$pid" 2>/dev/null || true
  echo "$v $kind rc=$rc $(grep -Eo 'batch command executed successfully|Plug-in crashed|image data' "$out" | tail -1)"
  return "$rc"
}

SAFE="$BASE/realglib/evidence/safe.jif"
ATK="$BASE/live/evidence/gdb-liveptr-8192.jif"
run_case vuln safe "$SAFE" && ok "pristine plug-in loads safe 4x4 JIF" || no "pristine safe control"
run_case fixed safe "$SAFE" && ok "fixed plug-in loads safe 4x4 JIF" || no "fixed safe control"
set +e
run_case vuln attack "$ATK"; VRC=$?
run_case fixed attack "$ATK"; FRC=$?
set -e
echo "ATTACK RC vuln=$VRC fixed=$FRC (script-fu may hang after an error; rc is observation only)"
grep -q 'fatal error: Segmentation fault' "$EVID/fixedctl-vuln-attack.log" \
  && ok "pristine plug-in faults on the 8 KiB attack JIF" || no "vulnerable attack fault"
! grep -q 'SHIM_PATCH' "$EVID/fixedctl-vuln-attack.log" \
  && ok "attack run carried no LD_PRELOAD shim" || no "shim present in attack run"
grep -q 'Error reading image data' "$EVID/fixedctl-fixed-attack.log" \
  && ok "fixed plug-in rejects the wrapping JIF" || no "fixed rejection"
! grep -q 'Segmentation fault' "$EVID/fixedctl-fixed-attack.log" \
  && ok "fixed plug-in did not fault" || no "fixed fault"

echo "TOTAL: $PASS PASS / $FAIL FAIL"
echo "CEILING: a locally rebuilt plug-in control is not a live published fixed build; no chosen-address write, dereference, command or r5 claim."
exit $((FAIL > 0))
