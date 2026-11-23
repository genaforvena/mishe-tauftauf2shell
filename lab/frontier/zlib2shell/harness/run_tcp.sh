#!/usr/bin/env bash
# zlib2shell — live gzip-over-TCP server experiment for CVE-2026-85091.
# Builds the server from the pinned 1.3.2 tarball with only gzwrite.c swapped;
# drives vulnerable/fixed x stalled/draining peers on a plant-started 127.0.0.1
# listener, plus a plain-build gdb readback of peer-supplied bytes.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SRC="$ROOT/src"
OUT="$HERE/tcp-evidence"
mkdir -p "$OUT"
TMP="$(mktemp -d /tmp/zlib2shell-tcp.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ck() { if [ "$2" = "1" ]; then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
hr() { sha256sum "$1" | awk '{print $1}'; }
g() { grep -E "^$2=" "$1" | head -1 | cut -d= -f2-; }

TARBALL_SHA=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
PARENT_SHA=9b76b11e1aee82378a234a6f63fa2a40623e32315e4023ab498555ea5428b43c
FIXED_SHA=a3289b4dc38c5470c34b14908c921fdf3dbb0e78c9e344aa0cb3d535d6292c10
SERVER_SHA=6acbfd28ab5e19b58078dbb4829df035dd989e64c9b4f16ab72c17b033b2af58
ck PIN_TARBALL "$([ "$(hr "$SRC/zlib-1.3.2.tar.gz")" = "$TARBALL_SHA" ] && echo 1 || echo 0)"
PROBE_SHA=4de435162e7e48797b68f47215dd0a0253f1d6d0f891b9213925fb9c5abcae6c
ck PIN_FIXED "$([ "$(hr "$SRC/gzwrite.c.fixed")" = "$FIXED_SHA" ] && echo 1 || echo 0)"
ck PIN_TCP_SERVER "$([ "$(hr "$HERE/tcp_server.c")" = "$SERVER_SHA" ] && echo 1 || echo 0)"
ck PIN_TCP_PROBE "$([ "$(hr "$HERE/tcp_probe.py")" = "$PROBE_SHA" ] && echo 1 || echo 0)"
if [ ! -f "$SRC/zlib-1.3.2/configure" ]; then
  tar xzf "$SRC/zlib-1.3.2.tar.gz" -C "$SRC"
fi

build() { # name blob compiler flags
  local name="$1" blob="$2" cc="$3" flags="$4"
  local dir="$TMP/build-$name"
  mkdir -p "$dir"
  cp -r "$SRC/zlib-1.3.2/." "$dir/"
  cp "$blob" "$dir/gzwrite.c"
  ( cd "$dir" && CC="$cc" CFLAGS="$flags" ./configure --static > "$OUT/build-$name.log" 2>&1 \
    && make -s -j4 >> "$OUT/build-$name.log" 2>&1 \
    && "$cc" $flags -I. "$HERE/tcp_server.c" libz.a -o "$TMP/srv-$name" >> "$OUT/build-$name.log" 2>&1 )
}
ASAN='-fsanitize=address -fno-omit-frame-pointer -g -O0'
build vuln-asan "$SRC/gzwrite.c.parent" gcc "$ASAN"
build fixed-asan "$SRC/gzwrite.c.fixed" gcc "$ASAN"
build vuln-plain "$SRC/gzwrite.c.parent" gcc '-g -O0'
ck BUILDS "$([ -x "$TMP/srv-vuln-asan" ] && [ -x "$TMP/srv-fixed-asan" ] && [ -x "$TMP/srv-vuln-plain" ] && echo 1 || echo 0)"

case_run() { # name binary mode
  python3 "$HERE/tcp_probe.py" --binary "$2" --mode "$3" --out "$OUT/$1.txt" > "$OUT/$1.summary" 2>&1
  cat "$OUT/$1.summary"
}
case_run vuln-stall "$TMP/srv-vuln-asan" stall
case_run fixed-stall "$TMP/srv-fixed-asan" stall
case_run vuln-drain "$TMP/srv-vuln-asan" drain
case_run vuln-slowdrain "$TMP/srv-vuln-asan" slowdrain
case_run vuln-gdb "$TMP/srv-vuln-plain" gdb

VULN="$OUT/vuln-stall.txt"; FIX="$OUT/fixed-stall.txt"; DRAIN="$OUT/vuln-drain.txt"
ck TCP_VULN_REQUEST_DELIVERED "$([ "$(g "$VULN" REQ_BYTES)" = 100000 ] && echo 1 || echo 0)"
ck TCP_VULN_STALL_SHORT_WRITE "$([ -n "$(g "$VULN" WRITTEN)" ] && [ "$(g "$VULN" WRITTEN)" != 100000 ] && echo 1 || echo 0)"
ck TCP_VULN_ASAN_OVERFLOW "$(grep -q 'heap-buffer-overflow' "$VULN" && grep -q 'gz_vacate' "$VULN" && grep -q 'WRITE of size' "$VULN" && grep -q '16384-byte region' "$VULN" && echo 1 || echo 0)"
ck TCP_VULN_ASAN_NONZERO_RC "$([ "$(g "$OUT/vuln-stall.summary" SERVER_RC)" != 0 ] && echo 1 || echo 0)"
ck TCP_FIXED_CLEAN "$([ "$(g "$OUT/fixed-stall.summary" SERVER_RC)" = 0 ] && ! grep -q AddressSanitizer "$FIX" && grep -q 'PRINTF_RC=1' "$FIX" && echo 1 || echo 0)"
ck TCP_DRAIN_CLEAN "$([ "$(g "$OUT/vuln-drain.summary" SERVER_RC)" = 0 ] && ! grep -q AddressSanitizer "$DRAIN" && grep -q 'PRINTF_RC=1' "$DRAIN" && echo 1 || echo 0)"
ck TCP_DRAIN_REQUEST_DELIVERED "$([ "$(g "$DRAIN" REQ_BYTES)" = 100000 ] && echo 1 || echo 0)"
ck TCP_SLOWDRAIN_ALSO_OVERFLOWS "$(grep -q 'heap-buffer-overflow' "$OUT/vuln-slowdrain.txt" && grep -q 'gz_vacate' "$OUT/vuln-slowdrain.txt" && echo 1 || echo 0)"
ck TCP_PEER_BYTES_READBACK "$(grep -q 'PEER_BYTE_CHECK=PASS' "$OUT/vuln-gdb.summary" && echo 1 || echo 0)"

cat "$OUT/vuln-stall.summary" "$OUT/fixed-stall.summary" "$OUT/vuln-drain.summary" \
  "$OUT/vuln-slowdrain.summary" "$OUT/vuln-gdb.summary" | grep -E '^(SERVER_RC|REQ_BYTES|WRITTEN|PRINTF_RC|SERVER_DONE|HAS_|GDB_|SRC_|DST[0-9]+_|PEER_BYTE_CHECK)=' > "$OUT/tcp-trace.txt"
echo "TCP_TRACE_SHA256=$(hr "$OUT/tcp-trace.txt")"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
