#!/bin/bash
# php2shell rung 2 — mod_php consumer (Apache prefork, loopback, ASan/UBSan build).
#
# Why Apache: the advisory's confirmed-exploit SAPI is mod_php; this is the
# consumer-reality check for the same three OOM shapes already proven negative
# on cli-server (see php2shell-rung2-cli-server.sh for the shape definitions).
# mod_php keeps a prefork child alive across requests (MaxRequestsPerChild 0,
# single worker), so each shape is followed by a probe on the SAME child.
#
# Usage: bash lab/repro/php2shell-rung2-modphp.sh <php-lib-so> [outdir]
#   php-lib-so: .../lab/build/php-8.4.26-apache-asan/sapi/apache2handler/.libs/libphp.so
#
# Needs: apache2 2.4.58 (noble), started as the current user, non-root,
# loopback-only Listen 127.0.0.1:18099, ServerRoot lab/apache2root.
# ASan is preloaded into the parent httpd so it is inherited by children;
# apache2 dup2()s the ErrorLog onto fd 2 of every child, so sanitizer
# output from the worker lands in logs/error_log.

set -u
PHPLIB=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(basename "$(dirname "$(dirname "$PHPLIB")")")-modphp
ROOT=$(cd "$(dirname "$0")/../apache2root" && pwd)
LOG="$OUT/rung2-modphp-$LABEL.log"
CONF="$ROOT/run-httpd.conf"
PORT=18099
mkdir -p "$OUT"
: > "$LOG"

[ -f "$PHPLIB" ] || { echo "no such lib: $PHPLIB" >&2; exit 1; }

sed "s|^#LoadModule php_module PHPLIB|LoadModule php_module $PHPLIB|" \
    "$ROOT/conf/httpd.conf" > "$CONF"

httpd_start() {
    LD_PRELOAD="$(clang -print-file-name=libasan.so):$(clang -print-file-name=libubsan.so)" \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1 \
        /usr/sbin/apache2 -d "$ROOT" -f "$CONF" -k start >> "$LOG" 2>&1
}
httpd_stop() {
    LD_PRELOAD="$(clang -print-file-name=libasan.so):$(clang -print-file-name=libubsan.so)" \
    /usr/sbin/apache2 -d "$ROOT" -f "$CONF" -k stop >> "$LOG" 2>&1
    for _ in $(seq 1 50); do
        python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),1)" 2>/dev/null \
            || return 0
        sleep 0.2
    done
}

http() { # http METHOD PATH BODYFILE OUTFILE
    python3 - "$PORT" "$1" "$2" "$3" "$4" <<'EOF'
import socket, sys
port, method, path, bodyf, outf = sys.argv[1:]
data = open(bodyf,'rb').read() if bodyf != '-' else b''
req = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
       f"Content-Type: application/x-www-form-urlencoded\r\n"
       f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode()
with socket.create_connection(("127.0.0.1", int(port)), timeout=60) as s:
    s.sendall(req + data)
    buf = b''
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            buf += b"\n[[client timeout]]"; break
        if not chunk: break
        buf += chunk
open(outf,'wb').write(buf)
EOF
}
body() { python3 -c 'import sys;print(sys.stdin.buffer.read().decode("utf8","replace").split("\r\n\r\n",1)[-1][:300].replace(chr(10)," | "))'; }
probe() { http GET /probe.php - "$OUT/rung2-modphp-$LABEL-probe.out"; body < "$OUT/rung2-modphp-$LABEL-probe.out"; }
pnum() { printf '%s' "$1" | tr -cd '0-9'; }

wait_up() {
    for _ in $(seq 1 50); do
        python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),1)" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

verdict() {
    echo "== verdict scan (log: $LOG)"
    if grep -qE 'AddressSanitizer|runtime error|SEGV|Assertion|SUMMARY|Aborted' "$LOG"; then
        echo "SIGNAL: sanitizer/assert/death evidence found"
        grep -nE 'AddressSanitizer|runtime error|SEGV|Assertion|SUMMARY|Aborted' "$LOG" | head -20
    else
        echo "no sanitizer/assert/death evidence — shapes consumed cleanly (negative)"
    fi
}

trap 'httpd_stop; rm -f "$CONF"' EXIT

httpd_stop >/dev/null 2>&1
httpd_start || { echo "start failed"; exit 1; }
wait_up || { echo "never came up"; exit 1; }

P1=$(probe); CPID=$(pnum "${P1#alive:}")
echo "-- initial probe: $P1"
# sanity: the answering child must carry libasan
if [ -n "$CPID" ] && grep -q libasan "/proc/$CPID/maps" 2>/dev/null; then
    echo "   child $CPID has libasan mapped: yes"
else
    echo "   FATAL: child pid='$CPID' has no libasan in maps — ASan not live in worker"; exit 1
fi

# --- s1: OOM during request parsing (618 shape), consumer = forced shutdown
python3 -c "print('a=' + 'x'*6*1024*1024, end='')" > /tmp/oombody.bin
http POST /probe.php /tmp/oombody.bin "$OUT/rung2-modphp-$LABEL-s1resp.out"
echo "  s1 oom-resp-tail: $(body < "$OUT/rung2-modphp-$LABEL-s1resp.out")"
sleep 0.5
P2=$(probe)
echo "  s1 followup probe: $P2  (same child: $([ "$(pnum "${P2#alive:}")" = "$CPID" ] && echo yes || echo NO))"

# --- s2: OOM during user code (runtime bailout), then same-child probe
http POST /oom.php - "$OUT/rung2-modphp-$LABEL-s2resp.out"
echo "  s2 oom-resp-tail: $(body < "$OUT/rung2-modphp-$LABEL-s2resp.out")"
sleep 0.5
P3=$(probe)
echo "  s2 followup probe: $P3  (same child: $([ "$(pnum "${P3#alive:}")" = "$CPID" ] && echo yes || echo NO))"

# --- s3: vendor's oom_pending_at_shutdown shape (OOM inside a shutdown func)
http POST /oomshut.php - "$OUT/rung2-modphp-$LABEL-s3resp.out"
echo "  s3 oom-resp-tail: $(body < "$OUT/rung2-modphp-$LABEL-s3resp.out")"
sleep 0.5
P4=$(probe)
echo "  s3 followup probe: $P4  (same child: $([ "$(pnum "${P4#alive:}")" = "$CPID" ] && echo yes || echo NO))"

# --- s4: 619-style stale-handler probe. Request N registers a user error
# handler and completes NORMALLY (release fast-shutdown path may leave
# EG(user_error_handler) stale); request N+1 parse-OOMs (s1 shape). If the
# stale handler were invoked, its marker would appear in the N+1 response
# tail or the log, and ASan would flag the freed-closure call.
http POST /seteh.php - "$OUT/rung2-modphp-$LABEL-s4resp.out"
echo "  s4 seteh-resp-tail: $(body < "$OUT/rung2-modphp-$LABEL-s4resp.out")"
http POST /probe.php /tmp/oombody.bin "$OUT/rung2-modphp-$LABEL-s4oom.out"
echo "  s4 oom-resp-tail: $(body < "$OUT/rung2-modphp-$LABEL-s4oom.out")"
if grep -q 'STALE-HANDLER-FIRED' "$OUT/rung2-modphp-$LABEL-s4oom.out"; then
    echo "  s4 SIGNAL: stale user error handler was invoked in request N+1"
else
    echo "  s4: stale handler NOT invoked in request N+1 (source-read claim reproduced: init_executor re-UNDEFs before php_hash_environment)"
fi
sleep 0.5
P5=$(probe)
echo "  s4 followup probe: $P5  (same child: $([ "$(pnum "${P5#alive:}")" = "$CPID" ] && echo yes || echo NO))"

verdict
httpd_stop
