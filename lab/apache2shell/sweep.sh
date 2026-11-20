#!/usr/bin/env bash
# Loopback-only ASan sweep for CVE-2026-119618.
# Usage: sweep.sh VERSION PORT SHAPE FILL CONNS STREAMS DURATION [LOGLEVEL]
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BASE="$REPO/lab/frontier/apache2root"
V="${1:?version}"; PORT="${2:?port}"; SHAPE="${3:?shape}"; FILL="${4:?fill}"
CONNS="${5:-8}"; STREAMS="${6:-100}"; DURATION="${7:-20}"; LEVEL="${8:-http2:trace3}"
TAG="$V-p$PORT-$SHAPE-f$FILL-$(date -u +%H%M%S)"
PREFIX="$BASE/install-$V-asan"
CONF="$HERE/run/sweep-$TAG.conf"
ERR="$HERE/logs/sweep-$TAG.error.log"
OUT="$HERE/logs/sweep-$TAG.stdout.log"
ACCESS="$HERE/logs/sweep-$TAG.access.log"
ASANPFX="$HERE/logs/asan-$TAG"
DRIVE="$HERE/logs/sweep-$TAG.drive.log"
mkdir -p "$HERE/run" "$HERE/logs"
MODS="authn_core authz_core authz_host unixd mime log_config logio headers dir alias reqtimeout setenvif filter http2 cgi version"
{
  echo "ServerRoot \"$PREFIX\""
  echo "PidFile \"$HERE/run/sweep-$TAG.pid\""
  echo "Listen 127.0.0.1:$PORT"
  for m in $MODS; do echo "LoadModule ${m}_module modules/mod_${m}.so"; done
  echo "ServerName localhost"
  echo "ErrorLog \"$ERR\""
  echo "LogLevel $LEVEL"
  echo 'LogFormat "%h %l %u %t \"%r\" %>s %b" common'
  echo "CustomLog \"$ACCESS\" common"
  echo "Protocols h2c http/1.1"
  echo "H2Direct on"
  echo "H2MaxSessionStreams 400"
  echo "DocumentRoot \"$BASE/htdocs\""
  echo "<Directory \"$BASE/htdocs\">"; echo "    Require all granted"; echo "</Directory>"
  echo "ScriptAlias /cgi-bin/ \"$BASE/cgi-bin/\""
  echo "<Directory \"$BASE/cgi-bin\">"; echo "    Require all granted"; echo "    Options +ExecCGI"; echo "    SetHandler cgi-script"; echo "</Directory>"
} > "$CONF"

ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:log_path=$ASANPFX" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
  "$PREFIX/bin/httpd" -f "$CONF" -DFOREGROUND > "$OUT" 2>&1 &
HPID=$!
trap 'kill $HPID 2>/dev/null; wait $HPID 2>/dev/null' EXIT
for i in $(seq 1 80); do
  if curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null; then break; fi
  sleep 0.25
done
echo "== $TAG: server pid $HPID, driving =="
(cd "$HERE" && python3 drive.py --port "$PORT" --fill "$FILL" --shape "$SHAPE" \
   --connections "$CONNS" --streams "$STREAMS" --duration "$DURATION") > "$DRIVE" 2>&1
RC=$?
sleep 1
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true
echo "drive_rc=$RC $(cat "$DRIVE")"
echo "access_lines=$(wc -l < "$ACCESS" 2>/dev/null || echo 0)"
echo "== ASan reports =="
if compgen -G "$ASANPFX.*" > /dev/null; then
  for f in "$ASANPFX".*; do echo "--- $f"; sed -n '1,60p' "$f"; done
else
  echo "(none)"
fi
echo "== error-log markers =="
grep -Ein 'AddressSanitizer|runtime error|SEGV|segmentation|child pid|crash|abort|AH0.*(exit|sig)' "$ERR" | tail -30 || echo "(none)"
echo "== artifact prefix: $TAG =="
