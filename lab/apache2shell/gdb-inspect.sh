#!/usr/bin/env bash
# Loopback-only gdb capture of the 2.4.70 child SIGSEGV.
# gdb intercepts SIGSEGV before Apache's sig_coredump handler, giving the
# real faulting stack (ASan's own handler is overwritten by ap_fatal_signal_setup).
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BASE="$REPO/lab/frontier/apache2root"
V="${1:-2.4.70}"; PORT="${2:-7185}"; FILL="${3:-78}"; DUR="${4:-25}"
TAG="$V-gdb-p$PORT-f$FILL-$(date -u +%H%M%S)"
PREFIX="$BASE/install-$V-asan"
CONF="$HERE/run/$TAG.conf"
GDBOUT="$HERE/logs/$TAG.gdb.log"
ERR="$HERE/logs/$TAG.error.log"
ACCESS="$HERE/logs/$TAG.access.log"
OUT="$HERE/logs/$TAG.stdout.log"
mkdir -p "$HERE/run" "$HERE/logs"
MODS="authn_core authz_core authz_host unixd mime log_config logio headers dir alias reqtimeout setenvif filter http2 cgi version"
{
  echo "ServerRoot \"$PREFIX\""
  echo "PidFile \"$HERE/run/$TAG.pid\""
  echo "Listen 127.0.0.1:$PORT"
  for m in $MODS; do echo "LoadModule ${m}_module modules/mod_${m}.so"; done
  echo "ServerName localhost"
  echo "ErrorLog \"$ERR\""
  echo "LogLevel info"
  echo 'LogFormat "%h %l %u %t \"%r\" %>s %b" common'
  echo "CustomLog \"$ACCESS\" common"
  echo "Protocols h2c http/1.1"
  echo "H2Direct on"
  echo "H2MaxSessionStreams 400"
  echo "StartServers 1"
  echo "ServerLimit 1"
  echo "ThreadsPerChild 64"
  echo "MinSpareThreads 1"
  echo "MaxSpareThreads 64"
  echo "MaxRequestWorkers 64"
  echo "DocumentRoot \"$BASE/htdocs\""
  echo "<Directory \"$BASE/htdocs\">"; echo "    Require all granted"; echo "</Directory>"
  echo "ScriptAlias /cgi-bin/ \"$BASE/cgi-bin/\""
  echo "<Directory \"$BASE/cgi-bin\">"; echo "    Require all granted"; echo "    Options +ExecCGI"; echo "    SetHandler cgi-script"; echo "</Directory>"
} > "$CONF"

# handle_segv=0 lets gdb own SIGSEGV; no ASan report is expected here.
ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:handle_segv=0:log_path=$HERE/logs/asan-$TAG" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'set confirm off' \
  -ex 'set follow-fork-mode child' \
  -ex 'set detach-on-fork on' \
  -ex 'handle SIGSEGV stop print nopass' \
  -ex 'handle SIGPIPE nostop noprint pass' \
  -ex 'handle SIGBUS stop print nopass' \
  -ex 'run -f '"$CONF"' -DFOREGROUND' \
  -ex 'printf "\n===== FAULT BACKTRACE =====\n"' \
  -ex 'bt 40' \
  -ex 'frame 0' \
  -ex "dump binary memory $HERE/logs/$TAG.mem.bin (\$rax-0x20000) (\$rax+0x20000)" \
  -ex "dump binary memory $HERE/logs/$TAG.stack.bin (\$rsp-0x4000) (\$rsp+0x4000)" \
  -ex 'printf "\n===== REGS ALL =====\n"' \
  -ex 'info registers' \
  -ex 'printf "\n===== DISASM AROUND RIP =====\n"' \
  -ex 'x/12i $rip-24' \
  -ex 'printf "\n===== APR_ALLOCATOR_FREE DISASM =====\n"' \
  -ex 'disassemble apr_allocator_free' \
  -ex 'printf "\n===== ARG REGISTERS (rdi=allocator rsi=pool) =====\n"' \
  -ex 'info registers rdi rsi rdx rcx r8 r9' \
  -ex 'printf "\n===== rdi bytes =====\n"' \
  -ex 'x/16gx $rdi' \
  -ex 'printf "\n===== rsi bytes =====\n"' \
  -ex 'x/16gx $rsi' \
  -ex 'printf "\n===== STACK AT FAULT =====\n"' \
  -ex 'x/12gx $rsp' \
  -ex 'printf "\n===== ALL THREADS =====\n"' \
  -ex 'info threads' \
  -ex 'thread apply all bt 8' \
  --args "$PREFIX/bin/httpd" > "$GDBOUT" 2>&1 &
GPID=$!
cleanup() {
  kill "$GPID" 2>/dev/null || true
  local hpid
  if [ -f "$HERE/run/$TAG.pid" ]; then
    hpid=$(cat "$HERE/run/$TAG.pid" 2>/dev/null)
    if [ -n "$hpid" ] && kill -0 "$hpid" 2>/dev/null; then
      kill -TERM "$hpid" 2>/dev/null || true
      sleep 1
      kill -KILL "$hpid" 2>/dev/null || true
    fi
  fi
  wait "$GPID" 2>/dev/null || true
}
trap cleanup EXIT
for i in $(seq 1 80); do
  curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null && break
  sleep 0.25
done
echo "== $TAG gdb pid $GPID, driving =="
(cd "$HERE" && python3 drive.py --port "$PORT" --fill "$FILL" --shape full \
   --connections 8 --streams 100 --duration "$DUR") 2>&1
sleep 3
cleanup
echo "== gdb output ($GDBOUT) =="
grep -n -E 'FAULT BACKTRACE|Program received signal|#[0-9]+ |REGS ALL|DISASM|ARG REGISTERS|rdi bytes|rsi bytes|ALL THREADS|inferior|exited' "$GDBOUT" | head -160 || true
echo "== error-log markers =="
grep -E 'AH00051|Segmentation' "$ERR" | head -10 || echo "(none)"
echo "== artifact: $TAG =="
