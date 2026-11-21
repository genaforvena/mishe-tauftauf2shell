#!/usr/bin/env python3
"""Adjacent-lane experiment: H2PushDiarySize 0 + debug-logging NULL deref.

Same mod_http2 subsystem as CVE-2026-119618, next bug in the 2.4.71 fix
series (httpd CHANGES 2.4.71: "Fix a crash creating an HTTP/2 session with
'H2PushDiarySize 0' and debug logging enabled", h2_session.c:1054-1069).

2.4.70: h2_push_diary_create(pool, 0) -> NULL (h2_push.c:549-555), then
        session->push_diary->dtype at h2_session.c:1068 dereferences NULL
        when APLOGcdebug(c) is true.
2.4.71: ternary guards at :1068-1069 replace the deref with 0.

Loopback-only. One h2c request per build. Grade is recorded, not asserted.
"""
import os
import signal
import subprocess
import sys
import time

from h2client import H2Connection, ConnectionClosed, ProtocolError, default_headers

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir,
                                    "frontier", "apache2root"))
LOGS = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOGS, exist_ok=True)


def conf_for(version, port):
    root = os.path.join(BASE, "install-%s-asan" % version)
    pid = os.path.join(BASE, "run", "pushdiary-%s.pid" % version)
    err = os.path.join(LOGS, "pushdiary-%s-error.log" % version)
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
LogLevel debug
Protocols h2c http/1.1
H2Direct on
H2PushDiarySize 0
DocumentRoot "{base}/htdocs"
<Directory "{base}/htdocs">
    Require all granted
</Directory>
""".format(root=root, pid=pid, port=port, err=err, base=BASE)


def probe(version, port):
    conf = os.path.join(BASE, "run", "pushdiary-%s.conf" % version)
    with open(conf, "w") as f:
        f.write(conf_for(version, port))
    err = os.path.join(LOGS, "pushdiary-%s-error.log" % version)
    if os.path.exists(err):
        os.unlink(err)
    httpd = os.path.join(BASE, "install-%s-asan" % version, "bin", "httpd")
    # -X: single process, so a session-setup NULL deref kills the listener
    # and is directly observable via the child return code.
    srv = subprocess.Popen([httpd, "-X", "-f", conf],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.0)
    outcome = "server-exited-early"
    try:
        conn = H2Connection("127.0.0.1", port, timeout=3.0)
        conn.handshake()
        conn.send_request_headers(1, default_headers())
        conn.sock.settimeout(2.0)
        try:
            conn.read_frame()
            outcome = "response-received"
        except (OSError, ConnectionClosed, ProtocolError):
            outcome = "connection-died"
        conn.close()
    except (OSError, ProtocolError, ConnectionClosed) as e:
        outcome = "handshake-failed: %s" % type(e).__name__
    alive = srv.poll() is None
    if alive:
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()
    out = srv.stdout.read().decode("utf-8", "replace") if srv.stdout else ""
    log = ""
    if os.path.exists(err):
        with open(err, "r", errors="replace") as f:
            log = f.read()
    return dict(version=version, port=port, outcome=outcome, rc=srv.returncode,
                stdout=out[-1500:], error_log=log[-2500:])


def main():
    for version, port in (("2.4.70", 7270), ("2.4.71", 7271)):
        r = probe(version, port)
        print("=== %s port %d ===" % (version, port))
        print("outcome=%s rc=%s" % (r["outcome"], r["rc"]))
        if r["stdout"].strip():
            print("server-stdout:\n" + r["stdout"])
        if r["error_log"].strip():
            print("error-log:\n" + r["error_log"])
        print(flush=True)


if __name__ == "__main__":
    main()
