#!/usr/bin/env python3
"""Map which raw bytes this httpd accepts in an HTTP/2 field value.

Loopback only. Starts a private 2.4.70 instance on 127.0.0.1:<port>, sends one
h2c request per candidate byte in a field value, reports the stream result,
then terminates its own httpd tree. No external network access.
"""
import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASE = REPO / "lab/frontier/apache2root"
PREFIX = BASE / "install-2.4.70-asan"
sys.path.insert(0, str(HERE))
from h2client import H2Connection

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7216
CONF = HERE / "run" / ("alphabet-probe-%d.conf" % PORT)
PIDFILE = HERE / "run" / ("alphabet-probe-%d.pid" % PORT)
MODS = ("authn_core authz_core authz_host unixd mime log_config logio headers "
        "dir alias reqtimeout setenvif filter http2 cgi version")


def start_server():
    CONF.parent.mkdir(parents=True, exist_ok=True)
    with CONF.open("w") as f:
        f.write('ServerRoot "%s"\nPidFile "%s"\nListen 127.0.0.1:%d\n'
                % (PREFIX, PIDFILE, PORT))
        for m in MODS.split():
            f.write("LoadModule %s_module modules/mod_%s.so\n" % (m, m))
        f.write('ServerName localhost\nLogLevel info\n'
                'ErrorLog "%s"\nLogFormat "%%h %%l %%u %%t \\"%%r\\" %%>s %%b" common\n'
                'CustomLog "%s" common\n'
                'Protocols h2c http/1.1\nH2Direct on\n'
                'StartServers 1\nServerLimit 1\nThreadsPerChild 64\n'
                'DocumentRoot "%s"\n<Directory "%s">\n    Require all granted\n</Directory>\n'
                % (HERE / "run" / ("alphabet-probe-%d.error.log" % PORT),
                   HERE / "run" / ("alphabet-probe-%d.access.log" % PORT),
                   BASE / "htdocs", BASE / "htdocs"))
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=0:handle_segv=0"
    return subprocess.Popen([str(PREFIX / "bin/httpd"), "-f", str(CONF),
                             "-DFOREGROUND"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=env)


def stop_server(proc):
    try:
        pid = int(PIDFILE.read_text().strip())
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (FileNotFoundError, ValueError, ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def probe(byte):
    conn = H2Connection("127.0.0.1", PORT, timeout=3.0)
    try:
        conn.handshake()
        conn.send_request_headers(1, [(":method", "GET"), (":scheme", "http"),
                                      (":authority", "localhost"),
                                      (":path", "/index.html"),
                                      ("x-probe", b"A" + bytes([byte]) + b"B")],
                                  end_stream=True)
        kind, payload = conn.read_until_response(1)
        if kind == "headers":
            return "200" if b"\x88" in payload else "headers:" + payload.hex()
        if kind == "rst":
            return "RST:%d" % struct.unpack(">I", payload[:4])[0]
        if kind == "goaway":
            return "GOAWAY:%d" % struct.unpack(">I", payload[4:8])[0]
        return kind
    except Exception as exc:
        return "%s:%s" % (type(exc).__name__, str(exc)[:50])
    finally:
        conn.close()


def main():
    proc = start_server()
    try:
        for _ in range(100):
            try:
                c = H2Connection("127.0.0.1", PORT, timeout=2.0)
                c.handshake()
                c.close()
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise SystemExit("server did not start; see %s" % CONF)
        print("byte   result   (2.4.70, h2c, one field value per connection)")
        for b in (0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x20, 0x7e, 0x7f, 0x80, 0xff):
            print("0x%02x   %s" % (b, probe(b)), flush=True)
    finally:
        stop_server(proc)


if __name__ == "__main__":
    main()
