#!/usr/bin/env python3
"""Loopback-only fake gpg for the read_status EOF early-return path.

Writes exactly FAKE_GPG_LEN bytes (default 1024) with no LF to GPGME's
--status-fd, with a chosen marker at offset 1000, then exits so the pipe
reaches EOF.  No callback error is needed: with readpos=1024 the next
read_status() reallocs and takes the nread==0 early return before the
buffer pointer writeback.  --version is answered so GPGME can set engine
info without a real gpg binary.  No network and no filesystem writes.
"""
import os
import sys

args = sys.argv[1:]
if args and args[0] == "--version":
    sys.stdout.write("gpg (GnuPG) 2.2.40\n")
    sys.exit(0)

fd = None
for i, arg in enumerate(args):
    if arg == "--status-fd" and i + 1 < len(args):
        fd = int(args[i + 1])
        break
if fd is None:
    sys.exit(0)

n = int(os.environ.get("FAKE_GPG_LEN", "1024"))
marker = os.environ.get("FAKE_GPG_MARKER", "H")
prefix = "[GNUPG:] GOOD "
if n < len(prefix) + 1:
    sys.exit(2)
payload = list("A" * (n - len(prefix)))
if len(payload) > 1000 - len(prefix):
    payload[1000 - len(prefix)] = marker
os.write(fd, (prefix + "".join(payload)).encode())
sys.exit(0)
