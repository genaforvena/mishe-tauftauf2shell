#!/usr/bin/env python3
"""W172: send one HEIF file over loopback to reencode_wire and capture output.

Usage: wire_client.py DRIVER INPUT.heif OUTPUT.heif [retain]
Prints the driver's combined stdout/stderr and its exit code. The driver binds
127.0.0.1:0 itself; this client only connects to the port it prints.
"""
import socket
import subprocess
import sys

driver, inp, outp = sys.argv[1:4]
retain = len(sys.argv) > 4 and sys.argv[4] == "retain"
cmd = [driver, outp] + (["retain"] if retain else [])
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
port = None
while port is None:
    line = proc.stdout.readline()
    if not line:
        break
    print(line, end="")
    if line.startswith("WIRE_PORT "):
        port = int(line.split()[1])
if port is None:
    print("CLIENT no WIRE_PORT; rc=", proc.wait())
    sys.exit(1)
with open(inp, "rb") as f:
    payload = f.read()
with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
    s.sendall(payload)
rest = proc.stdout.read()
if rest:
    print(rest, end="")
rc = proc.wait()
print("CLIENT driver_rc=%d" % rc)
