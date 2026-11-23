#!/bin/bash
# Three-case replay against the plant-started, non-ASan pinned gdbserver on
# loopback: chosen-length attack, well-formed safe packet, short attack.
# The plain build survives the write long enough to answer the wire, then
# faults during teardown; the safe and short packets exit cleanly.
set -u
BIN=${1:-lab/build/gdbserver-633ae02-plain/gdbserver/gdbserver}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
mkdir -p "$E"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
  if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}

bash "$HERE/live_run.sh" "$BIN" attack 64 34611 plain-verify-attack-64 \
  >"$E/plain-verify-attack-64.out" 2>&1
bash "$HERE/live_run.sh" "$BIN" safe 16 34612 plain-verify-safe-16 \
  >"$E/plain-verify-safe-16.out" 2>&1
bash "$HERE/live_run.sh" "$BIN" attack 8 34613 plain-verify-attack-8 \
  >"$E/plain-verify-attack-8.out" 2>&1

has "$E/plain-verify-attack-64.out" "CLIENT_RC=0 SERVER_RC=139" \
  "plain-attack-64-teardown-sigsegv"
has "$E/plain-verify-attack-64.out" "QTDPsrc_REPLY=OK" \
  "plain-attack-64-wire-answer-ok"
has "$E/plain-verify-attack-64.out" "GETTLS_REPLY=E01" \
  "plain-attack-64-no-threaddb"
has "$E/plain-verify-safe-16.out" "CLIENT_RC=0 SERVER_RC=0" \
  "plain-safe-16-clean-exit"
has "$E/plain-verify-safe-16.out" "QTDPsrc_REPLY=OK" \
  "plain-safe-16-wire-answer-ok"
has "$E/plain-verify-attack-8.out" "CLIENT_RC=0 SERVER_RC=0" \
  "plain-attack-8-clean-exit"

cat "$E"/plain-verify-*.out "$E"/live-live-plain-verify-*.log 2>/dev/null \
  | grep -aE '^(CLIENT_RC=|QTDP|INITIAL=|GETTLS)' \
  | sed -E -e 's/port [0-9]+/port PORT/g' \
  >"$E/plain-normalized.txt"
printf 'PLAIN_NORMALIZED_HASH=%s\n' \
  "$(sha256sum "$E/plain-normalized.txt" | cut -d' ' -f1)"
printf 'PLAIN_SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
