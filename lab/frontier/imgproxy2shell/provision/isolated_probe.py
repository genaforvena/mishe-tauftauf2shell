#!/usr/bin/env python3
"""Single-request loopback-only probe: isolate one case from http_probe.py's loop.

Usage: isolated_probe.py BINARY LIBDIR TAG REQUEST_PATH [TIMEOUT]

http_probe.py runs five cases in one imgproxy process with WORKERS=1 and
CONCURRENCY=1; a case behind a stalled request never reaches imgproxy and its
timeout is queue starvation, not an observation of that fixture. This probe
runs exactly one GET in a fresh process. No external address is contacted.
"""
import http.client
import http.server
import os
import subprocess
import sys
import threading
import time

import http_probe as p

binary, libdir, tag, request_path = sys.argv[1:5]
timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 8.0

srv = http.server.ThreadingHTTPServer((p.SRC_HOST, p.SRC_PORT), p.Source)
threading.Thread(target=srv.serve_forever, daemon=True).start()
env = dict(os.environ)
env.update({
    "IMGPROXY_BIND": f"{p.PROXY_HOST}:{p.PROXY_PORT}",
    "IMGPROXY_BASE_URL": f"http://{p.SRC_HOST}:{p.SRC_PORT}/",
    "IMGPROXY_WORKERS": "1",
    "IMGPROXY_CONCURRENCY": "1",
    "IMGPROXY_LOG_LEVEL": "info",
    "LD_LIBRARY_PATH": libdir,
    "IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES": "true",
})
logpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       f"http-isolated-{tag}.log")
log = open(logpath, "wb")
proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    if not p.wait_port(p.PROXY_HOST, p.PROXY_PORT):
        print(f"PROXY_LISTEN=FAIL tag={tag}")
        sys.exit(2)
    started = time.monotonic()
    status, body, err = "-", "", ""
    try:
        conn = http.client.HTTPConnection(p.PROXY_HOST, p.PROXY_PORT, timeout=timeout)
        conn.request("GET", f"/insecure/{request_path}",
                     headers={"Host": p.PROXY_HOST})
        resp = conn.getresponse()
        status = resp.status
        body = resp.read(600).decode("utf-8", "replace").replace("\n", "\\n")
        conn.close()
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    print(f"ISOLATED tag={tag} path={request_path} status={status} "
          f"elapsed={elapsed:.2f} err={err!r} body={body[:400]!r} "
          f"log={logpath}", flush=True)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    log.flush()
    log.close()
    srv.shutdown()
