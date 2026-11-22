#!/usr/bin/env python3
"""Normalize root-owned raw live-pty evidence into tracked deterministic text."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw"
EV = ROOT / "evidence"
EV.mkdir(exist_ok=True)

CASES = [
    "w122-vuln-n3f",
    "w122-vuln-n301",
    "w122-vuln-n374",
    "w122-vuln-n300",
    "w122-fixed-n301b",
    "w122-fixed-n3b",
]

KEEP_LOG = (
    "using channel", "Connect:", "sent [LCP Conf", "No auth is possible",
    "ignoring duplicate", "Terminating on signal",
)
KEEP_ASAN = (
    "ERROR: AddressSanitizer", "WRITE of size", "#0 ", "#1 ", "#2 ",
    "#3 ", "#4 ", "#5 ", "is located 0 bytes", "is located 36 bytes",
    "is located 32 bytes", "SUMMARY:",
)


def norm(line: str) -> str:
    line = re.sub(r"==\d+==", "==PID==", line)
    line = re.sub(r"/dev/pts/\d+", "/dev/pts/N", line)
    line = re.sub(r"0x[0-9a-fA-F]{4,}", "0xADDR", line)
    line = re.sub(r"magic 0xADDR", "magic 0xMAGIC", line)
    line = re.sub(r"/home/\S+?/(build-vuln|build-fixed)/", r"<\1>/", line)
    line = re.sub(r"BuildId: [0-9a-f]+", "BuildId: <ID>", line)
    line = re.sub(r"using channel \d+", "using channel N", line)
    return line.strip()

def collect(tag: str) -> str:
    out = [f"case {tag}"]
    summary_path = RAW / f"{tag}-summary.json"
    n = None
    if summary_path.exists():
        s = json.loads(summary_path.read_text())
        n = s.get("n")
        out += [f"binary={norm(s['binary'])}"]
        out += [f"{k}={s[k]}" for k in
                ("n", "frame_len", "process_rc", "survived_window")]
    log = RAW / f"{tag}-pppd.log"
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            if line.startswith("rcvd [LCP ConfReq"):
                out.append("rcvd [LCP ConfReq id=N with %s PAP AUTHTYPE CIs]" % (n or "?"))
            elif any(k in line for k in KEEP_LOG):
                out.append(norm(line))
    for path in sorted(RAW.glob(f"{tag}-asan.*")):
        for line in path.read_text(errors="replace").splitlines():
            if any(k in line for k in KEEP_ASAN):
                out.append(norm(line))
    frame = RAW / f"{tag}-frame.bin"
    if frame.exists():
        out.append("frame_sha256=" + hashlib.sha256(frame.read_bytes()).hexdigest())
    dedup = []
    for line in out:
        if not dedup or dedup[-1] != line:
            dedup.append(line)
    return "\n".join(dedup) + "\n"


def main() -> None:
    hashes = []
    for tag in CASES:
        path = EV / f"{tag}.txt"
        path.write_text(collect(tag))
        hashes.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
    (EV / "LIVE_HASHES.txt").write_text("".join(f"{h}  {n}\n" for n, h in hashes))
    print((EV / "LIVE_HASHES.txt").read_text(), end="")


if __name__ == "__main__":
    main()
