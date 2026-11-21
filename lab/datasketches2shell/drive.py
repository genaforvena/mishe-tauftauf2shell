#!/usr/bin/env python3
"""Loopback-only driver: boot the service (optionally under gdb), send one
length-prefixed hostile sketch image, collect its output. Never dials anything
except 127.0.0.1 that this script itself started."""
import argparse
import errno
import socket
import struct
import subprocess
import sys


def hostile_image(seed_path, count, value):
    seed = open(seed_path, "rb").read()
    need = 8 + count * 4
    buf = bytearray([value]) * need
    buf[: min(len(seed), need)] = seed[:need]
    buf[6] = count
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--port", type=int, default=38117)
    ap.add_argument("--count", type=int, default=64)
    ap.add_argument("--value", type=int, default=0x5A)
    ap.add_argument("--seed", required=True)
    ap.add_argument("--gdb-script")
    ap.add_argument("--stdin-feed", help="send this literal to process stdin")
    ap.add_argument("--extra", help="extra service argument, e.g. postalloc")
    ap.add_argument("--extra-argv", default="", help="comma-separated extra service args after port")
    ap.add_argument("--patch", default="", help="comma-separated coupon-relative offset=hexbyte")
    args = ap.parse_args()
    image = bytearray(hostile_image(args.seed, args.count, args.value))
    for spec in args.patch.split(","):
        if not spec:
            continue
        off, val = spec.split("=")
        image[8 + int(off)] = int(val, 16)
    cmd = [args.bin, str(args.port)]
    if args.extra:
        cmd.append(args.extra)
    for x in args.extra_argv.split(","):
        if x:
            cmd.append(x)
    if args.gdb_script:
        cmd = ["gdb", "-q", "-batch", "-x", args.gdb_script, "--args"] + cmd
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
           "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.PIPE, text=True, bufsize=1, env=env)
    if args.stdin_feed:
        proc.stdin.write(args.stdin_feed + "\n")
        proc.stdin.flush()
    lines = []
    while True:
        line = proc.stdout.readline()
        if not line:
            print("DRIVER rv=no_listen", flush=True)
            print("".join(lines), end="")
            sys.exit(2)
        lines.append(line)
        print(line, end="", flush=True)
        if "SERVICE_LISTEN" in line:
            break
    try:
        with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
            s.sendall(struct.pack("!I", len(image)) + bytes(image))
            s.shutdown(socket.SHUT_WR)
            s.recv(64)
    except OSError as e:
        print(f"DRIVER client_error={e.errno}", flush=True)
    for line in proc.stdout:
        lines.append(line)
        print(line, end="", flush=True)
    rc = proc.wait(timeout=60)
    print(f"DRIVER image_bytes={len(image)} service_rc={rc}", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
