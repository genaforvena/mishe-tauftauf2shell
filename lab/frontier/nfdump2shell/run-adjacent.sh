#!/usr/bin/env bash
# nfdump2shell: replay the two-record receive-buffer shape with pinned
# Process_nfd. Offline; no socket. Vulnerable/fixed and attack/safe/icmp
# controls all run from the same verbatim pins used by run-all.sh.
set -u
cd "$(dirname "$0")"
H=harness
mkdir -p "$H/out"
CFLAGS="-O0 -g -fno-omit-frame-pointer -I$H -I$H/../pins"
gcc $CFLAGS -DVULN=1 -o "$H/out/adjacent-vuln"  "$H/adjacent.c" || exit 2
gcc $CFLAGS -DVULN=0 -o "$H/out/adjacent-fixed" "$H/adjacent.c" || exit 2

PASS=0; FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
need() { # FILE PATTERN LABEL
  if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi
}

VULN="$H/out/adjacent-vuln-attack.log"
FIX="$H/out/adjacent-fixed-attack.log"
SAFE="$H/out/adjacent-vuln-safe.log"
ICMP="$H/out/adjacent-vuln-icmp.log"

"$H/out/adjacent-vuln" attack > "$VULN" 2>&1
need "$VULN" 'STORE_OFF=48' 'attack store lands on record 2 header'
need "$VULN" 'R2_HDR_BEFORE=0b00400001000000' 'record 2 header valid before'
need "$VULN" 'R2_HDR_AFTER=9b50351f49010000' 'record 2 header clobbered by chosen value'
need "$VULN" 'R2_TYPE=20635 R2_SIZE=7989 R2_NUMELEM=329' 'record 2 header fields corrupted'
need "$VULN" 'NUM_RECORDS=1 FLOWS=1' 'second record dropped by collector'

"$H/out/adjacent-vuln" safe > "$SAFE" 2>&1
need "$SAFE" 'R2_HDR_AFTER=0b00400001000000' 'safe: record 2 header intact'
need "$SAFE" 'NUM_RECORDS=2 FLOWS=2' 'safe: both records processed'

"$H/out/adjacent-fixed" attack > "$FIX" 2>&1
need "$FIX" 'Corrupt nfd record' 'fixed: short element rejected'
need "$FIX" 'R2_HDR_AFTER=0b00400001000000' 'fixed: record 2 header intact'
need "$FIX" 'NUM_RECORDS=0 FLOWS=0' 'fixed: no records processed'

"$H/out/adjacent-vuln" icmp > "$ICMP" 2>&1
need "$ICMP" 'P2_BYTES_BEFORE=dead5a5a01000000' 'icmp: chosen bytes before swap'
need "$ICMP" 'P2_BYTES_AFTER=0000adde01000000' 'icmp: chosen bytes written past element'

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
