#!/usr/bin/env python3
"""Loopback-only fake gpg: emits one status line on GPGME's --status-fd.

Emits exactly one long or short [GNUPG:] GOOD line, with a chosen byte at
offset 1000 of the status arguments. --version is answered so GPGME can set
engine info without a real gpg binary. No network, no filesystem writes
except the optional argv log.
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

fd = None
for i, arg in enumerate(args):
    if arg == "--status-fd" and i + 1 < len(args):
        fd = int(args[i + 1])
        break
if fd is None:
    sys.exit(0)

n = int(os.environ.get("FAKE_GPG_LEN", "1200"))
marker = os.environ.get("FAKE_GPG_MARKER", "H")
payload = list("A" * n)
if n > 1000:
    payload[1000] = marker
os.write(fd, ("[GNUPG:] GOOD " + "".join(payload) + "\n").encode())
sys.exit(0)
