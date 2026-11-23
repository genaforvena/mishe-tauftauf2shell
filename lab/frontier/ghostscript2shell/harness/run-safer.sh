#!/bin/bash
# CVE-2026-125396 — rung-4 native control under -dSAFER (no command attempt).
# The font path must be explicitly permitted; without that, SAFER falls back to
# a built-in font and the injected cleartext never runs.
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
[ "$(srcsha ../exp/native-chain-safer.ps)" = \
  f22acdea7bfcfefc842e3e201181da1223b0b15b309626ad5701b5bdc0e45d96 ] \
  && ok "pin-safer-probe" || no "pin-safer-probe"

ABSINJ="$(pwd)/font-injected.pfa"
bin/gs-vuln -q -dNODISPLAY -dSAFER --permit-file-read="$ABSINJ" \
  ../exp/native-chain-safer.ps > "$E/safer-chain.out" 2>&1
bin/gs-fixed -q -dNODISPLAY -dSAFER --permit-file-read="$ABSINJ" \
  ../exp/native-chain-safer.ps > "$E/safer-chain-fixed.out" 2>&1

V="$E/safer-chain.out"
has "$V" 'PATH_CONTROL_BYTES_BEFORE=1' 'r4-safer-path-state-initial'
has "$V" 'PATH_CONTROL_OPERATOR_BEFORE=true' 'r4-safer-operator-true'
has "$V" 'PATH_CONTROL_BYTES_AFTER=0' 'r4-safer-native-zero-write'
has "$V" 'PATH_CONTROL_OPERATOR_AFTER=false' 'r4-safer-boundary-state-flipped'
has "$V" 'PATH_CONTROL_BYTES_RESTORED=1' 'r4-safer-restored'
has "$V" 'CLEAN_VALUE=12345' 'r4-safer-cleanup'
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }
hasnt "$V" '%pipe%' 'r4-safer-no-command-attempt'
has "$E/safer-chain-fixed.out" 'NO_STALE_REF' 'r4-safer-fixed-no-stale-ref'
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
