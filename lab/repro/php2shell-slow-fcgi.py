#!/usr/bin/env python3
"""php2shell stage-2 driver: sends a FastCGI request in timed chunks so the
harness can place a request_terminate_timeout kill wherever it wants (e.g.
just before or during a session pwrite). Loopback only.

Usage: slow-fcgi.py PORT SCRIPT_FILENAME BODYFILE [--param K=V ...]
       [--pre-delay SEC] [--chunk BYTES] [--rate BYTES_PER_SEC]
       [--hold SEC] [--timeout SEC]
Prints a JSON verdict: what the worker returned (or the connection error),
plus the wall time of each phase.
"""
import json
import socket
import struct
import sys
import time

VERSION = 1
BEGIN_REQUEST = 1
END_REQUEST = 3
PARAMS = 4
STDIN = 5
STDOUT = 6
STDERR = 7


def record(rtype, req_id, content=b""):
    pad = (-len(content)) % 8
    return (struct.pack("!BBHHBB", VERSION, rtype, req_id,
                        len(content), pad, 0) + content + b"\0" * pad)


def nvpair(name, value):
    n = name.encode() if isinstance(name, str) else name
    v = value.encode() if isinstance(value, str) else value

    def enc(x):
        if len(x) < 128:
            return bytes([len(x)])
        return struct.pack("!I", len(x) | 0x80000000)
    return enc(n) + enc(v) + n + v


def main(argv):
    port = int(argv[1])
    script = argv[2]
    body_file = argv[3]
    params = {
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.rsplit("/", 1)[-1],
        "DOCUMENT_ROOT": script.rsplit("/", 1)[0],
        "REQUEST_METHOD": "POST",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REDIRECT_STATUS": "200",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": str(0),  # fixed below
        "CONTENT_TYPE": "multipart/form-data; boundary=----XBOUND",
    }
    with open(body_file, "rb") as f:
        body = f.read()
    params["CONTENT_LENGTH"] = str(len(body))
    pre_delay = 0.0
    chunk = 65536
    rate = 0.0  # unlimited
    hold = 0.0
    slow_after = None
    timeout = 30.0
    rate2 = None
    i = 4
    while i < len(argv):
        if argv[i] == "--param" and i + 1 < len(argv):
            k, _, v = argv[i + 1].partition("=")
            params[k] = v
            i += 2
        elif argv[i] == "--pre-delay":
            pre_delay = float(argv[i + 1]); i += 2
        elif argv[i] == "--rate":
            rate = float(argv[i + 1]); i += 2
        elif argv[i] == "--slow-after":  # bytes after which --rate applies
            slow_after = int(argv[i + 1]); rate2 = None; i += 2
        elif argv[i] == "--fast-rate":  # rate for the first --slow-after bytes
            rate2 = float(argv[i + 1]); i += 2
        elif argv[i] == "--hold":
            hold = float(argv[i + 1]); i += 2
        elif argv[i] == "--timeout":
            timeout = float(argv[i + 1]); i += 2
        else:
            print("unknown arg", argv[i], file=sys.stderr)
            return 2

    chunk = min(chunk, 65535)
    out, err = b"", b""
    verdict = {"phase_times": {}}
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(record(BEGIN_REQUEST, 1,
                         struct.pack("!HB5x", 1, 0)))
        p = b"".join(nvpair(k, v) for k, v in params.items())
        s.sendall(record(PARAMS, 1, p))
        s.sendall(record(PARAMS, 1))
        verdict["phase_times"]["params_sent"] = round(time.time() - t0, 3)
        if pre_delay:
            time.sleep(pre_delay)
        verdict["phase_times"]["pre_delay_done"] = round(time.time() - t0, 3)
        # send the body per chunk/rate; --slow-after splits the body into a
        # fast prefix (e.g. the multipart part header) and a throttled suffix
        # (the file part content) so the worker sits in the upload read loop
        sent = 0
        while sent < len(body):
            if slow_after is not None:
                if sent < slow_after:
                    r = rate2  # None = unlimited
                    end = min(sent + chunk, slow_after)
                else:
                    r = rate
                    end = sent + chunk
            else:
                r = rate
                end = sent + chunk
            part = body[sent:end]
            if part:
                s.sendall(record(STDIN, 1, part))
                sent += len(part)
            if r:
                time.sleep(chunk / r)
            if slow_after is not None and sent >= slow_after and "slow_region" not in verdict["phase_times"]:
                verdict["phase_times"]["slow_region"] = round(time.time() - t0, 3)
        s.sendall(record(STDIN, 1))
        verdict["phase_times"]["body_sent"] = round(time.time() - t0, 3)
        verdict["bytes_sent"] = sent
        if hold:
            time.sleep(hold)
        # read the response
        while True:
            h = b""
            while len(h) < 8:
                c = s.recv(8 - len(h))
                if not c:
                    raise EOFError("connection closed")
                h += c
            ver, rtype, rid, clen, plen, _ = struct.unpack("!BBHHBB", h)
            content = b""
            while len(content) < clen:
                c = s.recv(clen - len(content))
                if not c:
                    raise EOFError("connection closed mid-record")
                content += c
            if plen:
                s.recv(plen)
            if rtype == STDOUT:
                out += content
            elif rtype == STDERR:
                err += content
            elif rtype == END_REQUEST:
                app_status, proto = struct.unpack("!IB3x", content[:8])
                verdict["end"] = {
                    "app_status": app_status, "protocol_status": proto,
                    "t": round(time.time() - t0, 3)}
                break
        verdict["status"] = "ok"
    except Exception as e:
        verdict["status"] = "error"
        verdict["error"] = repr(e)
        verdict["phase_times"]["error_t"] = round(time.time() - t0, 3)
    verdict["stdout_head"] = out[:80].decode("latin1")
    verdict["stderr_head"] = err[:200].decode("latin1")
    verdict["total"] = round(time.time() - t0, 3)
    print(json.dumps(verdict))
    return 1 if verdict["status"] == "error" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
