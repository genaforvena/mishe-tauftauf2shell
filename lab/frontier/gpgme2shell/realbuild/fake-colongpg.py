#!/usr/bin/env python3
"""Loopback-only fake gpg for the read_colon_line() realloc path.

GPGME gives the engine its colon pipe on stdout (--with-colons). This emits
exactly 1024 bytes with no LF on stdout: read_colon_line() consumes them all
(readpos reaches the 1024-byte buffer end), then its next call reallocs to
2048 before reading and sees EOF, returning without the pointer writeback at
engine-gpg.c:1728-1730. gpg->colon.buffer is left pointing at the block
realloc just freed. A status line carries the same chosen byte so an
in-process callback can log it; no callback error is used on either path.

No network, no filesystem writes.
"""
import os
import sys

args = sys.argv[1:]
if args and args[0] == "--version":
    sys.stdout.write("gpg (GnuPG) 2.2.40\n")
    sys.exit(0)

log = os.environ.get("FAKE_GPG_LOG")
if log:
    with open(log, "a") as f:
        f.write(repr(args) + "\n")

marker = os.environ.get("FAKE_COLON_MARKER", "H").encode("ascii")[0]
length = int(os.environ.get("FAKE_COLON_LEN", "1024"))

status_fd = None
for i, arg in enumerate(args):
    if arg == "--status-fd" and i + 1 < len(args):
        status_fd = int(args[i + 1])
        break
if status_fd is not None:
    payload = bytearray(b"A" * 1200)
    payload[1000] = marker
    os.write(status_fd, b"[GNUPG:] GOOD " + bytes(payload) + b"\n")

colon = bytearray(b"A" * length)
if length > 1000:
    colon[1000] = marker
os.write(1, bytes(colon))
sys.stdout.flush()
