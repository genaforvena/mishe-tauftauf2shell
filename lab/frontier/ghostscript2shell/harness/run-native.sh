#!/bin/bash
# CVE-2026-125396 — rung-4 native mechanics differential.
#   vulnerable 10.07.0 + type-confused font -> forged refs walk the live
#       interpreter pointer chain, write a benign marker to path_control_active,
#       and retarget one mul ref to sub for a single observable call
#   fixed 1484854e + same font -> no stale ref, no chain, no dispatch change
# Local files only; no network, no service, no command execution.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

[ "$(srcsha ../exp/native-chain.ps)" = \
  6b0ff3e41e63ed6954bfefcc2c63bc22f8e989cb1fb33268ab53a45111e56047 ] \
  && ok "pin-native-chain" || no "pin-native-chain"
[ "$(srcsha ../exp/native-dispatch.ps)" = \
  4fe8afa2d61efdeb818fa46e226d61a1fc862c89f66eef41e9d464caed92cb5b ] \
  && ok "pin-native-dispatch" || no "pin-native-dispatch"

run() {
    GS_FONT_PATH="$2" "$1" -q -dNODISPLAY -dNOSAFER "$3" > "$4" 2>&1
}
ABSINJ="$(pwd)/font-injected.pfa"

run bin/gs-vuln "$ABSINJ" ../exp/native-chain.ps "$E/native-chain.out"
run bin/gs-vuln "$ABSINJ" ../exp/native-dispatch.ps "$E/native-dispatch.out"
run bin/gs-fixed "$ABSINJ" ../exp/native-chain.ps "$E/native-chain-fixed.out"
run bin/gs-fixed "$ABSINJ" ../exp/native-dispatch.ps "$E/native-dispatch-fixed.out"

C="$E/native-chain.out"
for pair in 'DEVPTR= GXDEVICE=' 'GXDEVICE= MEM=' 'MEM= LIBCTX=' 'LIBCTX= CORE='; do
    set -- $pair
    grep -qF "$1" "$C" && grep -qF "$2" "$C" && ok "chain-$1" || no "chain-$1"
done
has "$C" 'PATH_CONTROL_BYTES=0' 'r4-chain-path-state-initial'
has "$C" 'PSTATE_WRITTEN=1'     'r4-chain-native-write'
has "$C" 'PATH_CONTROL_OPERATOR=true' 'r4-chain-state-observed'
has "$C" 'PSTATE_RESTORED=0'    'r4-chain-restored'
has "$C" 'CLEAN_VALUE=12345'    'r4-chain-cleanup'

D="$E/native-dispatch.out"
has "$D" 'SUB_DIFFERS=true' 'r4-distinct-op-pointers'
has "$D" 'BEFORE=319'       'r4-dispatch-before'
has "$D" 'CHANGED=18'       'r4-dispatch-retargeted'
has "$D" 'AFTER=319'        'r4-dispatch-restored'

for f in "$E/native-chain-fixed.out" "$E/native-dispatch-fixed.out"; do
    has "$f" 'NO_STALE_REF' "r4-fixed-$(basename "$f")"
done

{
  cat "$C" "$D"
} | sed -E 's#=/?[0-9]+#=ADDR#g; s#/[^ ]*/lab/frontier#lab/frontier#g' \
  > "$E/native-normalized.txt"
TRACE=$(srcsha "$E/native-normalized.txt")
printf 'NATIVE_TRACE_SHA256=%s\n' "$TRACE"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
