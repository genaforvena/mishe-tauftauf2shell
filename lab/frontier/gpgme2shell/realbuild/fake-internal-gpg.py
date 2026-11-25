#!/usr/bin/env python3
"""Loopback-only fake gpg for the internal-strdup groom experiment.

Emits a [GNUPG:] GET_LINE with an attacker-sized keyword (no LF before byte
1024, so read_status must realloc) followed by a long GOOD line whose argument
makes the victim's status monitor callback return an error. No network, no
filesystem writes. SHORT=1 emits only a short GOOD line as a safe control.
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

if os.environ.get("SHORT") == "1":
    os.write(fd, b"[GNUPG:] GOOD short\n")
    sys.exit(0)

keyword_len = int(os.environ.get("KEYWORD_LEN", "1020"))
marker = os.environ.get("FAKE_GPG_MARKER", "H")
keyword = list("A" * keyword_len)
if keyword_len > 1000:
    keyword[1000] = marker
good = "G" * 600
if len(good) > 1000:
    good[1000] = "G"
os.write(fd, ("[GNUPG:] GET_LINE " + "".join(keyword) + "\n"
              + "[GNUPG:] GOOD " + good + "\n").encode())
sys.exit(0)
