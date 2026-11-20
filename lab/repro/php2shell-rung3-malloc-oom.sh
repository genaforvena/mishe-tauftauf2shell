#!/bin/bash
# php2shell rung 3 — malloc-backed OOM with sanitizer-visible request memory.
#
# The stock ZEND MM (ZMM) serves emalloc from 2MB mmap pools, so ASan cannot
# see corruption inside a pool. This harness forces PHP's *system malloc*
# path while keeping the memory_limit bailout live:
#
#   USE_ZEND_ALLOC=0   -> custom_heap._malloc = tracked_malloc/allocation
#   USE_TRACKED_ALLOC=1 -> tracked_check_limit() still enforces memory_limit
#                          and calls zend_mm_safe_error() -> zend_error_noreturn
#                          (longjmp) when it is exceeded (8.4.26 zend_alloc.c
#                          2952-2965, 401-426). Every request allocation is a
#                          separate malloc block ASan can inspect.
#
# Source cross-check: without USE_TRACKED_ALLOC, malloc failure reaches
# __zend_malloc() -> zend_out_of_memory() = "Out of memory" + exit(1)
# (zend_alloc.c 3292-3299, 2930-2934), i.e. NO bailout, no corrupt state.
# A pre-exec RLIMIT_AS also breaks ASan itself (shadow reserve fails), so it
# is deliberately not used here. The tracked allocator is the faithful way
# to reproduce the advisory's "underlying allocation fails / longjmp while
# incomplete request memory is reachable" condition on these builds.
#
# Producers (vendor's Zend/tests/oom_request_parsing.phpt shapes):
#   A: php-cgi, OOM during automatic request parsing (startup failure).
#   B: php -S cli-server, OOM during parsing; this SAPI calls
#      php_request_shutdown() even after failed startup (cli_server.c:2311).
#   C: OOM in user code / in a shutdown function, then same-worker probe.
#
# Usage: bash lab/repro/php2shell-rung3-malloc-oom.sh <cli-php-bin> [outdir]
#   <cli-php-bin>: lab/build/php-<ver>-<mode>/sapi/cli/php
# Loopback only (127.0.0.1), local processes only.

set -u
PHP=$(readlink -f "$1")
BUILDDIR=$(dirname "$(dirname "$(dirname "$PHP")")")
CGI="$BUILDDIR/sapi/cgi/php-cgi"
LABEL=$(basename "$BUILDDIR" | sed 's/^php-//')
OUT=${2:-lab/build/evidence}
PORT=${PORT:-18121}
mkdir -p "$OUT"
LOG="$OUT/rung3-malloc-oom-$LABEL.log"
: > "$LOG"
D=$(mktemp -d)
WPID=
trap 'test -n "$WPID" && kill "$WPID" 2>/dev/null; rm -rf "$D"' EXIT

# shellcheck disable=SC2016
oom_env() {
    USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 \
    UBSAN_OPTIONS=halt_on_error=1 \
    "$@"
}

# ---------- A: php-cgi startup-parse OOM, three body shapes ---------------
printf '<?php echo "alive";' > "$D/target.php"
python3 -c "print('a=' + 'x'*6*1024*1024, end='')" > "$D/one.bin"
python3 -c "print('&'.join(f'k{i}=v{i}' for i in range(200000)), end='')" > "$D/many.bin"
python3 -c "print('a=' + 'x'*3*1024*1024 + '&' + '&'.join(f'k{i}=v{i}' for i in range(100000)), end='')" > "$D/mixed.bin"

for shape in one many mixed; do
    body="$D/$shape.bin"
    len=$(stat -c%s "$body")
    out="$OUT/rung3-malloc-oom-cgi-$LABEL-$shape.log"
    echo "== A/$shape: php-cgi POST startup-parse OOM ($len body bytes)" >> "$LOG"
    oom_env env \
        REQUEST_METHOD=POST \
        CONTENT_TYPE=application/x-www-form-urlencoded \
        CONTENT_LENGTH="$len" \
        SCRIPT_FILENAME="$D/target.php" \
        REDIRECT_STATUS=1 \
        "$CGI" -n -d memory_limit=8M -d post_max_size=1G \
            -d max_input_vars=10000000 -d html_errors=0 \
            < "$body" > "$out" 2>&1
    echo "   exit=$?  fatal: $(grep -m1 'Fatal error' "$out" | head -c 180)" >> "$LOG"
done

# ---------- B/C: persistent cli-server consumer ---------------------------
printf '<?php echo "alive:" . getmypid() . "\n";' > "$D/probe.php"
printf '<?php $a=[]; while(true){$a[]=str_repeat("x",1<<20);}' > "$D/oom.php"
printf '<?php register_shutdown_function(function(){$a=[];while(true){$a[]=str_repeat("x",1<<20);}});' > "$D/shutdown.php"

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

resp_body() { python3 -c 'import sys;print(sys.stdin.buffer.read().decode("utf8","replace").split("\r\n\r\n",1)[-1].replace(chr(10)," | ")[-260:])'; }
alive() {
    http GET /probe.php - "$D/probe.out"
    resp_body < "$D/probe.out"
}
wait_port_free() {
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
start_worker() {
    # exec inside the backgrounded subshell so $WPID IS the PHP process;
    # without exec $! is the wrapper subshell and kill/wait leak a worker.
    ( USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 \
      ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 \
      UBSAN_OPTIONS=halt_on_error=1 \
      exec "$PHP" -S "127.0.0.1:$PORT" -n -t "$D" \
        -d memory_limit=8M -d post_max_size=1G \
        -d max_input_vars=10000000 -d html_errors=0 \
    ) >> "$LOG" 2>&1 &
    WPID=$!
    for _ in $(seq 1 30); do
        kill -0 "$WPID" 2>/dev/null || break
        sleep 0.1
    done
    kill -0 "$WPID" 2>/dev/null || { echo "worker died on startup — see $LOG" >&2; return 1; }
}
probe1() {
    local body pid
    body=$(alive); pid=${body#alive:}; pid=${pid%% *}
    if [ "$pid" != "$WPID" ]; then
        echo "WARNING: probe pid $pid != worker $WPID; using $pid as baseline" >&2
    fi
    echo "$body"
}
probe_alive() { # probe after OOM; $WPID is the exec'd PHP process
    local body pid
    body=$(alive); pid=${body#alive:}; pid=${pid%% *}
    if [ "$pid" != "$WPID" ]; then
        echo "$body [PID CHANGED from $WPID to $pid]"
    else
        echo "$body [same PID $pid]"
    fi
}

for scen in s1_parse_oom s2_runtime_oom s3_shutdown_oom; do
    wait_port_free || { echo "port $PORT never freed before $scen" >> "$LOG"; break; }
    start_worker || break
    echo "-- B/C $scen: start=$(probe1)" >> "$LOG"
    case $scen in
        s1_parse_oom)     http POST /probe.php "$D/one.bin" "$D/$scen.resp" ;;
        s2_runtime_oom)   http POST /oom.php - "$D/$scen.resp" ;;
        s3_shutdown_oom)  http POST /shutdown.php - "$D/$scen.resp" ;;
    esac
    echo "   response: $(resp_body < "$D/$scen.resp")" >> "$LOG"
    sleep 0.3
    if kill -0 "$WPID" 2>/dev/null; then
        echo "   worker alive after OOM; probe=$(probe_alive)" >> "$LOG"
    else
        echo "   worker DIED after OOM (pid $WPID)" >> "$LOG"
    fi
    kill "$WPID" 2>/dev/null
    wait "$WPID" 2>/dev/null
    echo "   worker exit status=$?" >> "$LOG"
    WPID=
done

echo "== verdict scan (logs: $LOG + cgi shapes)" >> "$LOG"
if grep -hqE 'AddressSanitizer|runtime error:|SEGV|Assertion.*failed|SUMMARY:|zend_mm_heap corrupted' \
        "$LOG" "$OUT"/rung3-malloc-oom-cgi-"$LABEL"-*.log; then
    echo "SANITIZER/CRASH SIGNAL FOUND — inspect $LOG" | tee -a "$LOG"
else
    echo "NEGATIVE: no ASan/UBSan/ASSERT/crash in malloc-backed OOM lane (record it)" | tee -a "$LOG"
fi
grep -c 'Fatal error: Allowed memory size' "$LOG" | sed 's/^/   OOM fatals in main log: /'
exit 0
