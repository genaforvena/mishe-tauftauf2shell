#!/bin/sh
# W198: vulnerable/fixed pair for the W186 real-consumer id_token lane.
# Usage: ./fixed-control-run.sh [fixed|vulnerable]
# Same loopback wire bytes for both variants; only the statically linked
# cjose changes (pinned v0.6.2.4 vs v0.6.2.4 + 8c51d245 length check).
# Listener is 127.0.0.1:18443 only, launched as gdb's child and stopped here.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
E="$HERE/evidence"
VARIANT=${1:-fixed}
case "$VARIANT" in
    fixed)
        CONF="$HERE/apache-idtoken-fixed.conf"
        GDBCMD="$HERE/gdb-idtoken-fixed.cmd"
        PIDFILE="$HERE/apache-idtoken-fixed.pid"
        GDBLOG="$E/gdb-idtoken-fixed.log"
        ERRLOG="$E/idtoken-fixed-apache_error.log"
        ;;
    vulnerable)
        CONF="$HERE/apache-idtoken-vulncontrol.conf"
        GDBCMD="$HERE/gdb-idtoken-vulncontrol.cmd"
        PIDFILE="$HERE/apache-idtoken-vulncontrol.pid"
        GDBLOG="$E/gdb-idtoken-vulncontrol.log"
        ERRLOG="$E/idtoken-vulncontrol-apache_error.log"
        ;;
    *) echo "BAD_VARIANT=$VARIANT" >&2; exit 2 ;;
esac

cleanup() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    if [ -n "${GDBPID:-}" ]; then
        kill "$GDBPID" 2>/dev/null || true
        wait "$GDBPID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

rm -rf /tmp/w2-oidc-cache-fixed /tmp/w2-apache-idtoken-fixed-run \
       /tmp/w2-oidc-cache-vulncontrol /tmp/w2-apache-idtoken-vulncontrol-run
mkdir -p /tmp/w2-oidc-cache-fixed /tmp/w2-apache-idtoken-fixed-run \
         /tmp/w2-oidc-cache-vulncontrol /tmp/w2-apache-idtoken-vulncontrol-run

timeout 120 gdb -q -batch -x "$GDBCMD" \
    --args /usr/sbin/apache2 -f "$CONF" -X \
    > "$E/gdb-idtoken-${VARIANT}control-stdout.log" 2>&1 &
GDBPID=$!

ready=0
i=0
while [ "$i" -lt 80 ]; do
    if ss -ltn 'sport = :18443' | grep -q 18443; then ready=1; break; fi
    i=$((i + 1))
done
printf 'LISTENER_READY=%d VARIANT=%s\n' "$ready" "$VARIANT"

set +e
./probe-idtoken.py valid > "$E/idtoken-${VARIANT}control-valid-response.bin" 2>&1
printf 'VALID_RC=%d\n' "$?"
./probe-idtoken.py oversized > "$E/idtoken-${VARIANT}control-oversized-response.bin" 2>&1
printf 'OVERSIZED_RC=%d\n' "$?"
# The W186 crash was exposed by a follow-up GET after the oversized POST.
./follow-idtoken.py > "$E/idtoken-${VARIANT}control-follow-response.bin" 2>&1
printf 'FOLLOW_RC=%d\n' "$?"
sleep 2
set -e

UNWRAPS=$(grep -c W2I_AES_UNWRAP_KEY_REACHED "$GDBLOG" 2>/dev/null || true)
KWHITS=$(grep -c W2I_AES_KW_DECRYPT_REACHED "$GDBLOG" 2>/dev/null || true)
ABORTS=$(grep -ci 'invalid next size\|malloc(): corrupted\|free(): invalid' "$ERRLOG" 2>/dev/null || true)
printf 'APACHE_PID_FILE=%s\n' "$(cat "$PIDFILE" 2>/dev/null || echo none)"
printf 'UNWRAP_HITS=%s KW_DECRYPT_HITS=%s ABORT_HITS=%s\n' "${UNWRAPS:-0}" "${KWHITS:-0}" "${ABORTS:-0}"
printf 'FOLLOW=%s\n' "$(cat "$E/idtoken-${VARIANT}control-follow-response.bin")"
