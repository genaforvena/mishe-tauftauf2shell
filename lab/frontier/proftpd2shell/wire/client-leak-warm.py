#!/usr/bin/env python3
"""Warm the rewrite engine with a short STOR so `substr` is initialized."""
import io
import socket
import time
import ftplib

host, port, key = "127.0.0.1", 21904, "WARMKEY"
for _ in range(40):
    try:
        s = socket.create_connection((host, port), 1)
        s.close()
        break
    except OSError:
        time.sleep(0.25)

ftp = ftplib.FTP()
try:
    ftp.connect(host, port, timeout=8)
    ftp.login("labuser", "labpass")
    ftp.set_pasv(True)
    ftp.sock.settimeout(8)
    print("LOGIN_OK")
    try:
        ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
        print("WARM_STOR_OK")
    except Exception as exc:
        print("WARM_STOR_FAIL %s: %s" % (type(exc).__name__, str(exc)[:140]))
    print("NOOP=" + str(ftp.voidcmd("NOOP"))[:80])
except Exception as exc:
    print("CLIENT_FAIL %s: %s" % (type(exc).__name__, str(exc)[:200]))
finally:
    try:
        ftp.close()
    except Exception:
        pass
