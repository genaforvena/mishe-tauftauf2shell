#!/bin/bash
# CVE-2026-125396 — rung-4 PostScript-level UAF aliasing differential.
#   vulnerable 10.07.0 + type-confused font -> stale systemdict ref aliases a
#                                             live interpreter array after restore
#   fixed 1484854e      + same font           -> no stale ref at all
#   vulnerable 10.07.0  + unmodified font     -> no stale ref at all
# Local files only; no network, no service, no off-loopback probe.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
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
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

[ "$(srcsha uaf.ps)" = \
  34b6abffe3ed28648b57872b67d4ee91726d767e52ba1773dde2f2630b9eba8e ] \
  && ok "pin-uaf-probe" || no "pin-uaf-probe"
[ "$(srcsha font-injected.pfa)" = \
  ef164da0c9db3fa84ea2f5494dfc856c22fd65752336a48dbf24224ec386b1fa ] \
  && ok "pin-injected-font" || no "pin-injected-font"
[ "$(srcsha font-safe.pfa)" = \
  85649a2b1b2f86df9addfe0ccc27ae48ec2ea6ee1815e180a33d73d062b2a4c6 ] \
  && ok "pin-safe-font" || no "pin-safe-font"

run_case() {
    GS_FONT_PATH="$2" "$1" -q -dNODISPLAY -dNOSAFER uaf.ps > "$3" 2>&1
}
ABSINJ="$(pwd)/font-injected.pfa"
ABSSAFE="$(pwd)/font-safe.pfa"
run_case bin/gs-vuln "$ABSINJ" "$E/uaf-vuln-injected.out"
run_case bin/gs-fixed "$ABSINJ" "$E/uaf-fixed-injected.out"
run_case bin/gs-vuln "$ABSSAFE" "$E/uaf-vuln-safe.out"

V="$E/uaf-vuln-injected.out"
has "$V" 'SV_PRESENT=true'  'r4-vuln-stale-ref-present'
has "$V" 'SV_TYPE=stringtype' 'r4-vuln-stale-ref-is-string'
has "$V" 'SV_LEN=2048'       'r4-vuln-stale-ref-length'
has "$V" 'PRE_ALL_MARK=true' 'r4-vuln-live-slots-initialized'
has "$V" 'D1_HIT=true'       'r4-vuln-stale-write-changes-live-slot'
has "$V" 'D1_CHANGED_COUNT=1' 'r4-vuln-exactly-one-slot-changed'
has "$V" 'D2_LIVE_VALUE=305419898' 'r4-vuln-live-write-value'
has "$V" 'D2_STALE_B0=122' 'r4-vuln-live-write-reads-back-b0'
has "$V" 'D2_STALE_B1=86'  'r4-vuln-live-write-reads-back-b1'
has "$V" 'D2_STALE_B2=52'  'r4-vuln-live-write-reads-back-b2'
has "$V" 'D2_STALE_B3=18'  'r4-vuln-live-write-reads-back-b3'
has "$V" 'CLEAN_STALE_B0=120' 'r4-vuln-cleanup-restores-byte'

F="$E/uaf-fixed-injected.out"
has "$F" 'SV_PRESENT=false' 'r4-fixed-no-stale-ref'
has "$F" 'NO_STALE_REF'     'r4-fixed-guard-blocked-write'
hasnt "$F" 'D1_HIT=true'    'r4-fixed-no-aliasing'

S="$E/uaf-vuln-safe.out"
has "$S" 'SV_PRESENT=false' 'r4-safe-no-stale-ref'
has "$S" 'NO_STALE_REF'     'r4-safe-no-typecheck'
hasnt "$S" 'D1_HIT=true'    'r4-safe-no-aliasing'

{
  cat "$V" "$F" "$S"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/==[0-9]+==/==PID==/g' \
  > "$E/uaf-normalized.txt"
TRACE=$(srcsha "$E/uaf-normalized.txt")
printf 'UAF_TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
