#!/usr/bin/env python3
"""Lab-only orchestrator: run the loopback server and the same-socket flood,
with hard timeouts. All traffic stays on 127.0.0.1."""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out", "loopback")


def run(server, port, count, tag):
    sl = open(os.path.join(OUT, "flood-%s-server.log" % tag), "w")
    cl = open(os.path.join(OUT, "flood-%s-sender.log" % tag), "w")
    p = subprocess.Popen([server, str(port)], stdout=sl, stderr=subprocess.STDOUT,
                         cwd=HERE)
    time.sleep(0.3)
    q = subprocess.Popen([sys.executable, os.path.join(HERE, "loopback_flood.py"),
                          os.path.join(OUT, "ch.bin"), str(port), str(count)],
                         stdout=cl, stderr=subprocess.STDOUT, cwd=HERE)
    try:
        q.wait(timeout=15)
    except subprocess.TimeoutExpired:
        q.kill()
        print("FACT sender_timeout")
    try:
        p.wait(timeout=25)
        print("FACT server_rc=%d" % p.returncode)
    except subprocess.TimeoutExpired:
        p.kill()
        print("FACT server_timeout_killed")
    sl.close()
    cl.close()
    for name in ("sender", "server"):
        path = os.path.join(OUT, "flood-%s-%s.log" % (tag, name))
        lines = open(path, errors="replace").read().splitlines()
        print("=== %s (%d lines) ===" % (name, len(lines)))
        for line in lines[:12] + (["..."] if len(lines) > 20 else []) + lines[-8:]:
            print(line)


if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "server-plain")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18462
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    tag = sys.argv[4] if len(sys.argv) > 4 else "test"
    run(server, port, count, tag)
