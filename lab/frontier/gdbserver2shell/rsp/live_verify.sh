#!/bin/bash
# Three-case replay against real pinned gdbserver builds on loopback:
# vulnerable+attack, vulnerable+safe, fixed+attack. Both binaries must be
# ASan builds from the same 633ae02 source tree (the fixed one differs by
# the saved upstream fix hunk only).
set -u
VULN=${1:?need vulnerable gdbserver binary}
FIXED=${2:?need fixed gdbserver binary}
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
hasnt() {
  if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}

bash "$HERE/live_run.sh" "$VULN" attack 64 34581 live-vuln-attack-64 \
  >"$E/verify-vuln-attack-64.out" 2>&1
bash "$HERE/live_run.sh" "$VULN" safe 16 34582 live-vuln-safe-16 \
  >"$E/verify-vuln-safe-16.out" 2>&1
bash "$HERE/live_run.sh" "$FIXED" attack 64 34583 live-fixed-attack-64 \
  >"$E/verify-fixed-attack-64.out" 2>&1
has "$E/live-live-vuln-attack-64.log" "getpkt (\"QTDPsrc:1:0:cond:0:1:" "live-attack-packet-received"
f="$E/verify-vuln-attack-64.out"
has "$f" "QTDP_REPLY=OK" "live-tracepoint-created"
has "$f" "CLIENT_RC=0" "live-client-clean-exit"
has "$f" "SERVER_RC=134" "live-vuln-asan-abort"
has "$f" "AddressSanitizer: heap-buffer-overflow" "live-vuln-asan-report"
has "$f" "WRITE of size 1" "live-vuln-asan-write"
has "$f" "in hex2bin" "live-vuln-asan-decoder-frame"
has "$f" "in cmd_qtdpsrc" "live-vuln-asan-handler-frame"
has "$f" "gdbserver/tracepoint.cc:2547" "live-vuln-asan-handler-line"
has "$f" "gdbsupport/common-utils.cc:465" "live-vuln-asan-decoder-line"

f="$E/verify-vuln-safe-16.out"
has "$f" "QTDPsrc_REPLY=OK" "live-safe-reply-ok"
has "$f" "SERVER_RC=0" "live-safe-clean-exit"
hasnt "$E/live-live-vuln-safe-16.log" "AddressSanitizer" "live-safe-no-asan"

f="$E/verify-fixed-attack-64.out"
has "$f" "QTDPsrc_REPLY=E01" "live-fixed-rejects-attack"
has "$f" "SERVER_RC=0" "live-fixed-clean-exit"
hasnt "$E/live-live-fixed-attack-64.log" "AddressSanitizer" "live-fixed-no-asan"

cat "$E"/verify-*.out "$E"/live-live-*.log 2>/dev/null \
  | grep -aE '^(CLIENT_RC=|QTDP|INITIAL=|==[0-9]+==ERROR:|WRITE of size|SUMMARY: AddressSanitizer:|\[remote\] getpkt)' \
  | sed -E -e 's/==[0-9]+==/==PID==/g' -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
           -e 's/port [0-9]+/port PORT/g' \
  > "$E/live-normalized.txt"
printf 'LIVE_NORMALIZED_HASH=%s\n' \
  "$(sha256sum "$E/live-normalized.txt" | cut -d' ' -f1)"
printf 'LIVE_SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
