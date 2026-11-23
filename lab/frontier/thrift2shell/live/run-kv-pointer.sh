#!/bin/bash
# Replay a crafted KV frame against a loopback server with ASLR off, so the
# glibc tcache link bytes embedded in the frame keep their addresses.
# Usage: ./run-kv-pointer.sh [vuln|fixed] [PORT] [FRAME]
set -u
cd "$(dirname "$0")" || exit 1
case "${1:-vuln}" in
  vuln)  server=./live-plain ;;
  asan)  server=./live-vuln ;;
  fixed) server=./live-fixed ;;
  *) echo "usage: $0 [vuln|fixed] [PORT] [FRAME]" >&2; exit 2 ;;
esac
port="${2:-29420}"
frame="${3:-kv-ptr14.bin}"
log="results/kv-pointer-${1:-vuln}-$(basename "$frame" .bin).log"
mkdir -p results
rm -f "$log"
ASAN_OPTIONS=detect_leaks=0 timeout 8 setarch -R "$server" server "$port" >"$log" 2>&1 &
spid=$!
sleep 1
python3 raw-client.py "$port" "$frame" 1
wait "$spid"
src=$?
echo "CASE=${1:-vuln} SERVER_RC=$src LOG=$log"
grep -E 'PROCESS_REACHED|SIGSEGV|free\(\)|ERROR: AddressSanitizer|WRITE of size|munmap|Aborted|Segmentation' "$log" | head -20 || true
