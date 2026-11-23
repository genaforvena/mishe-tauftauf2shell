#!/bin/bash
# CVE-2026-63626 / GHSA-pc66-j6r6-49x9 — Mongoose IPv6CP peer-length overflow.
# Every run re-extracts the four pinned function/struct slices from the
# byte-exact upstream blobs, checks SHA-256, builds plain and ASan variants,
# and drives rungs 1-4. No daemon, no listener, no network, no off-loopback.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc p-vuln p-fixed a-vuln-gcc a-vuln-clang a-fixed-gcc
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
count() {
    if [ "$(grep -cF "$2" "$1" 2>/dev/null)" = "$3" ]; then ok "$4"; else no "$4"; fi
}

# --- verbatim slices: re-extracted from pinned bytes on every run -----------
V=../src/l2_ppp.c.8bb65c64926d
F=../src/l2_ppp.c.751f14742dea
{ echo '#line 10 "l2_ppp.c.8bb65c64926d"'; sed -n '10,89p' "$V"; } > vuln/ppp_structs.inc
{ echo '#line 231 "l2_ppp.c.8bb65c64926d"'; sed -n '231,236p' "$V"; } > vuln/ppp_tx_frame.inc
{ echo '#line 277 "l2_ppp.c.8bb65c64926d"'; sed -n '277,290p' "$V"; } > vuln/find_opt.inc
{ echo '#line 350 "l2_ppp.c.8bb65c64926d"'; sed -n '350,416p' "$V"; } > vuln/ppp_handle_ipv6cp.inc
{ echo '#line 10 "l2_ppp.c.751f14742dea"'; sed -n '10,89p' "$F"; } > fixed/ppp_structs.inc
{ echo '#line 231 "l2_ppp.c.751f14742dea"'; sed -n '231,236p' "$F"; } > fixed/ppp_tx_frame.inc
{ echo '#line 278 "l2_ppp.c.751f14742dea"'; sed -n '278,291p' "$F"; } > fixed/find_opt.inc
{ echo '#line 351 "l2_ppp.c.751f14742dea"'; sed -n '351,418p' "$F"; } > fixed/ppp_handle_ipv6cp.inc
sha256sum -c SHA256SUMS > "$E/hashcheck.out" 2>&1 \
  && ok "sha256-manifest" || no "sha256-manifest"
count ../src/fix-751f1474.patch \
  '+  if (len < sizeof(*lcp) || len > lcpsz) return;' 2 'patch-lcp-guard'
count ../src/fix-751f1474.patch \
  '+  if (len < sizeof(*ipcp) || len > ipcpsz) return;' 2 'patch-ipcp-guard'
count ../src/fix-751f1474.patch \
  '+  if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;' 2 'patch-ipv6cp-guard'
count "$E/hashcheck.out" ': OK' 12 'all-12-pinned-files-match'
count fixed/ppp_handle_ipv6cp.inc \
  'if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;' 1 'fixed-guard-present'
count vuln/ppp_handle_ipv6cp.inc \
  'if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;' 0 'vuln-guard-absent'

# --- build ------------------------------------------------------------------
cc -O0 -g -std=gnu11 -o p-vuln driver.c 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -o p-fixed driver.c 2> "$E/build-p-fixed.log" \
  && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-gcc driver.c \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
if command -v clang >/dev/null 2>&1; then
  clang -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-clang driver.c \
    2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
else
  no "build-asan-clang-vuln"
fi
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -fsanitize=address -o a-fixed-gcc driver.c \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"

# --- rung 1: advisory arithmetic, no vulnerable function call ---------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'PEER_LEN=65535' 'r1-peer-chosen-16bit-len'
has "$E/arith-vuln.out" 'OPTS_WALK_LEN=65531' 'r1-find-opt-walk-extent'
has "$E/arith-vuln.out" 'TX_DATASZ=65535' 'r1-tx-copy-extent'
has "$E/arith-vuln.out" 'OVERFLOW_BYTES=64515' 'r1-tx-overflow-extent'

# --- rungs 2+4: chosen bytes land at chosen offsets past tx.buf ------------
./p-vuln plain > "$E/plain-vuln.out" 2>&1
has "$E/plain-vuln.out" 'TX_CALLS=2' 'r2-ack-and-req-transmitted'
has "$E/plain-vuln.out" 'GWIFC_HEX=2222222222222222' 'r2-peer-ifcid-accepted'
has "$E/plain-vuln.out" 'CANARY0=5a' 'r4-chosen-5a-at-canary-offset-0'
has "$E/plain-vuln.out" 'CANARY17=3c' 'r4-chosen-3c-at-canary-offset-17'
hasnt "$E/plain-vuln.out" 'CANARY0=cc' 'r4-canary-0-overwritten'
hasnt "$E/plain-vuln.out" 'CANARY17=cc' 'r4-canary-17-overwritten'

# --- rung 3a: ASan READ in find_opt on a 14-byte Configure-Request ---------
./a-vuln-gcc asan-read > "$E/vuln-gcc-asan-read.out" 2>&1
has "$E/vuln-gcc-asan-read.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-read-overflow'
has "$E/vuln-gcc-asan-read.out" 'READ of size 1' 'r3-gcc-asan-read1'
has "$E/vuln-gcc-asan-read.out" '14-byte region' 'r3-gcc-asan-read-at-frame-end'
has "$E/vuln-gcc-asan-read.out" 'in find_opt' 'r3-gcc-asan-read-in-find-opt'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang asan-read > "$E/vuln-clang-asan-read.out" 2>&1
  has "$E/vuln-clang-asan-read.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-read-overflow'
  has "$E/vuln-clang-asan-read.out" 'in find_opt' 'r3-clang-asan-read-in-find-opt'
fi

# --- rung 3b: ASan WRITE past tx.buf in ppp_tx_frame -----------------------
./a-vuln-gcc asan-write > "$E/vuln-gcc-asan-write.out" 2>&1
has "$E/vuln-gcc-asan-write.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-write-overflow'
has "$E/vuln-gcc-asan-write.out" 'WRITE of size' 'r3-gcc-asan-write'
has "$E/vuln-gcc-asan-write.out" 'in ppp_tx_frame' 'r3-gcc-asan-write-in-tx'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang asan-write > "$E/vuln-clang-asan-write.out" 2>&1
  has "$E/vuln-clang-asan-write.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-write-overflow'
  has "$E/vuln-clang-asan-write.out" 'in ppp_tx_frame' 'r3-clang-asan-write-in-tx'
fi

# --- fixed control: upstream guard rejects before read or write ------------
./p-fixed plain > "$E/fixed-plain.out" 2>&1
has "$E/fixed-plain.out" 'TX_CALLS=0' 'fixed-no-transmission'
has "$E/fixed-plain.out" 'GWIFC_HEX=0000000000000000' 'fixed-no-peer-ifcid'
has "$E/fixed-plain.out" 'CANARY0=cc' 'fixed-canary-0-intact'
has "$E/fixed-plain.out" 'CANARY17=cc' 'fixed-canary-17-intact'
./a-fixed-gcc asan-write > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'TX_CALLS=0' 'fixed-asan-rejects'

# --- safe control: well-formed 14-byte frame stays inside both buffers -----
./p-vuln safe > "$E/vuln-safe.out" 2>&1
has "$E/vuln-safe.out" 'TX_CALLS=2' 'safe-vuln-acks-normally'
has "$E/vuln-safe.out" 'CANARY0=cc' 'safe-vuln-canary-0-intact'
has "$E/vuln-safe.out" 'CANARY17=cc' 'safe-vuln-canary-17-intact'
./a-vuln-gcc safe > "$E/vuln-gcc-asan-safe.out" 2>&1
hasnt "$E/vuln-gcc-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-vuln-asan-clean'

# --- deterministic normalized trace: no PID, address, path or frame number --
{
  cat "$E/hashcheck.out"
  cat "$E/arith-vuln.out"
  grep -E '^(VARIANT|TX_CALLS|GWIFC_HEX|CANARY0|CANARY17)' "$E/plain-vuln.out"
  grep -E 'ERROR: AddressSanitizer|READ of size|WRITE of size|#[0-9]+ .*in (find_opt|ppp_tx_frame)' \
    "$E/vuln-gcc-asan-read.out" "$E/vuln-gcc-asan-write.out"
  grep -E '^(VARIANT|TX_CALLS|CANARY0|CANARY17)' "$E/fixed-plain.out"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
