#!/usr/bin/env python3
"""Normalize live-wire evidence; variable ports, PIDs and addresses removed."""
import glob
import os
import re
import sys

out_dir = sys.argv[1]
lines = []
for path in sorted(glob.glob(os.path.join(out_dir, "wire-*.*.log"))):
    name = os.path.basename(path)
    for raw in open(path, errors="replace"):
        line = raw.rstrip("\r\n")
        keep = (line.startswith("CLIENT_CONNECT_RC=")
                or line.startswith("CLIENT_READ_BEGIN")
                or line.startswith("CLIENT_READ_RC=")
                or "ERROR: AddressSanitizer" in line
                or "WRITE of size" in line
                or "opReadMultiVars()" in line
                or "located 0 bytes after" in line
                or line.startswith("SUMMARY: AddressSanitizer")
                or line.startswith("DECLARED_DATA_LENGTH=")
                or line.startswith("SERVER_DONE"))
        if not keep:
            continue
        line = re.sub(r"==\d+==", "==PID==", line)
        line = re.sub(r"port=\d+", "port=PORT", line)
        line = re.sub(r"BIND=127\.0\.0\.1:\d+", "BIND=127.0.0.1:PORT", line)
        line = re.sub(r"ACCEPT from [0-9a-fA-F:.]+:\d+", "ACCEPT from PEER", line)
        line = re.sub(r"0x[0-9a-fA-F]+", "ADDR", line)
        lines.append("%s %s" % (name, line))
sys.stdout.write("\n".join(lines) + "\n")
