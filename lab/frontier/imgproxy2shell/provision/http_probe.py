#!/usr/bin/env python3
"""Throwaway loopback-only probe: imgproxy 4.0.0 -> crafted TIFF over HTTP.

Starts an ephemeral source server on 127.0.0.1, launches one imgproxy binary
bound to 127.0.0.1, sends GET requests through imgproxy's normal unauthenticated
image URL path, and records status/body/timing plus imgproxy stderr.
No external address is contacted.
"""
import http.client
import http.server
import os
import socket
import subprocess
import sys
import threading
import time

SRC_HOST, SRC_PORT = "127.0.0.1", 18081
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18080
REAL = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/libvips2shell/real"

FILES = {
    "/manyband.tif": open(os.path.join(REAL, "manyband.tif"), "rb").read(),
    "/safe.tif": open(os.path.join(REAL, "safe.tif"), "rb").read(),
    "/tiff9999.tif": open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tiff9999.tif"), "rb").read(),
    "/fine.tif": open(os.path.join(REAL, "fine.tif"), "rb").read(),
}


class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FILES.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/tiff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def wait_port(host, port, seconds=12.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    binary, libdir, tag = sys.argv[1], sys.argv[2], sys.argv[3]
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 25.0

    srv = http.server.ThreadingHTTPServer((SRC_HOST, SRC_PORT), Source)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"SOURCE bind={SRC_HOST}:{SRC_PORT} files=" +
          ",".join(f"{k}={len(v)}" for k, v in FILES.items()), flush=True)

    env = dict(os.environ)
    env.update({
        "IMGPROXY_BIND": f"{PROXY_HOST}:{PROXY_PORT}",
        "IMGPROXY_BASE_URL": f"http://{SRC_HOST}:{SRC_PORT}/",
        "IMGPROXY_WORKERS": "1",
        "IMGPROXY_CONCURRENCY": "1",
        "IMGPROXY_LOG_LEVEL": "info",
        "LD_LIBRARY_PATH": libdir,
        "IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES": "true",
    })
    logpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           f"http-{tag}.log")
    log = open(logpath, "wb")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)

    try:
        if not wait_port(PROXY_HOST, PROXY_PORT):
            print(f"PROXY_LISTEN=FAIL tag={tag}")
            return 2
        print(f"PROXY_LISTEN=OK tag={tag} bind={PROXY_HOST}:{PROXY_PORT}", flush=True)
        for name, path in (("safe", "rs:fill:16:16/plain/safe.tif"),
                           ("manyband", "rs:fill:16:16/plain/manyband.tif"),
                           ("manyband_tiff", "rs:fill:16:16/f:tiff/plain/manyband.tif"),
                           ("tiff9999_tiff", "rs:fill:16:16/f:tiff/plain/tiff9999.tif"),
                           ("fine_tiff", "rs:fill:16:16/f:tiff/plain/fine.tif")):
            started = time.monotonic()
            status, body, err = "-", "", ""
            try:
                conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=timeout)
                conn.request("GET", f"/insecure/{path}", headers={"Host": PROXY_HOST})
                resp = conn.getresponse()
                status = resp.status
                body = resp.read(600).decode("utf-8", "replace").replace("\n", "\\n")
                conn.close()
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
            elapsed = time.monotonic() - started
            print(f"REQ tag={tag} case={name} status={status} "
                  f"elapsed={elapsed:.2f} err={err!r} body={body[:400]!r}",
                  flush=True)
        return 0
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
        with open(logpath, "rb") as fh:
            tail = fh.read()[-3000:].decode("utf-8", "replace")
        print(f"PROXY_LOG tag={tag} path={logpath} tail={tail!r}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
