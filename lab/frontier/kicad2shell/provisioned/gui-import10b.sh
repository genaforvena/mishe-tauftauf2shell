#!/bin/bash
# W186: fixed-build KiCad 10.0.8 Symbol Editor import of a .SchLib under Xvfb.
# Seeded config makes the first-run wizard/privacy prompts absent; the Tools
# menu is at x267 and Symbol Editor at y112 (the old driver used 8.0.8 coords).
# Usage: gui-import10b.sh <tag> <SchLib-path> [gdb]
set -u
TAG="$1"; FILE="$2"; MODE="${3:-plain}"
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/kicad2shell
P="$BASE/provisioned"
DISP=":19$(( $(date +%s) % 10 ))"
export LD_LIBRARY_PATH="$P/apt-kicad/usr/lib/x86_64-linux-gnu:$P/apt-kicad8/usr/lib/x86_64-linux-gnu:$P/apt-kicad10/usr/lib/x86_64-linux-gnu:$P/apt-kicad10-deps/usr/lib/x86_64-linux-gnu:$P/apt-kicad10-deps/usr/lib"
export KICAD_CONFIG_HOME="$P/kicad10-config"
rm -f "$P/g10b-$TAG.log" "$P/g10b-$TAG.png" "$P/g10b-$TAG.rc"
Xvfb "$DISP" -screen 0 1280x1024x24 -nolisten tcp -ac >"$P/g10b-$TAG-xvfb.log" 2>&1 &
XV=$!
sleep 2
export DISPLAY="$DISP"
if [ "$MODE" = gdb ]; then
  gdb -q -batch -ex run -ex 'bt 45' --args "$P/apt-kicad10/usr/bin/eeschema" >"$P/g10b-$TAG.log" 2>&1 &
else
  "$P/apt-kicad10/usr/bin/eeschema" >"$P/g10b-$TAG.log" 2>&1 &
fi
EE=$!
sleep 10
import -window root "$P/g10b-$TAG-boot.png" 2>/dev/null || true
xdotool mousemove 900 495 click 1; sleep 2
xdotool mousemove 267 11 click 1; sleep 1
import -window root "$P/g10b-$TAG-tools.png" 2>/dev/null || true
xdotool mousemove 320 112 click 1; sleep 6
import -window root "$P/g10b-$TAG-symed.png" 2>/dev/null || true
xdotool mousemove 60 152 click 1; sleep 1
xdotool mousemove 20 11 click 1; sleep 1
import -window root "$P/g10b-$TAG-file.png" 2>/dev/null || true
xdotool mousemove 60 288; sleep 1
xdotool mousemove 345 288 click 1; sleep 4
xdotool key ctrl+l; sleep 1
xdotool type --delay 20 "$FILE"; sleep 1
import -window root "$P/g10b-$TAG-typed.png" 2>/dev/null || true
xdotool key Return; sleep 10
import -window root "$P/g10b-$TAG.png" 2>/dev/null || true
if ! kill -0 "$EE" 2>/dev/null; then wait "$EE"; RC=$?; echo "$RC" > "$P/g10b-$TAG.rc"; echo "RC=$RC"; else echo alive > "$P/g10b-$TAG.rc"; fi
echo "TAG=$TAG FILE=$FILE MODE=$MODE DISPLAY=$DISP EE=$EE"
echo "--- log tail:"; tail -40 "$P/g10b-$TAG.log"
kill -9 "$EE" "$XV" 2>/dev/null
echo DONE
