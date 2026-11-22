#!/usr/bin/env python3
"""Write deterministic evidence for the chosen-value pppd NAK experiments."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
OUT = ROOT / "chosen" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)

TAGS = [
    "w123-plain-t1500",
    "w123-plain-t1504",
    "w123-plain-t1528",
    "w123-asan-vuln-t1500",
    "w123-asan-fixed-t1500",
]
ADDR = re.compile(r"0x[0-9a-f]{10,}")
PATH = re.compile(r"/[^\s]*?/(?:src|raw)/build-(?:vuln|fixed)(?:-plain)?/")
PID = re.compile(r"process \d+")

def norm(line: str) -> str:
    line = PATH.sub("BUILD/", line)
    line = ADDR.sub("0xADDR", line)
    line = PID.sub("process PID", line)
    line = re.sub(r"^==\d+==", "==PID==", line)
    return line.rstrip()


def log_facts(path: Path) -> list[str]:
    if not path.exists():
        return ["log: MISSING"]
    lines = path.read_text(errors="replace").splitlines()
    out = []
    for prefix in ("rcvd [LCP ConfReq", "sent [LCP ConfNak"):
        hits = [l for l in lines if l.startswith(prefix)]
        if not hits:
            out.append(f"{prefix}: none")
            continue
        out.append(f"{prefix}: {norm(hits[0])[:230]}")
    keys = (
        "ERROR: AddressSanitizer", "WRITE of size", "#0 ", "#2 ", "#4 ",
        "is located 0 bytes", "SUMMARY: AddressSanitizer",
        "LCP: ignoring duplicate",
    )
    for line in lines:
        if any(k in line for k in keys):
            out.append("asan/control: " + norm(line))
    return out


def main() -> None:
    hashes = []
    for tag in TAGS:
        summary = json.loads((RAW / f"{tag}-summary.json").read_text())
        gdb = (RAW / f"{tag}-gdb.txt").read_text(errors="replace")
        frame = (RAW / f"{tag}-frame.bin").read_bytes()
        lines = [
            f"=== {tag} ===",
            f"binary={'/'.join(Path(summary['binary']).parts[-3:])}",
            f"target_offset={summary['target_offset']}",
            f"pap_cis={summary['pap_cis']} async_cis={summary['async_cis']}",
            f"info_len={summary['info_len']} nak_bytes={summary['nak_bytes']}",
            f"ci_value={summary['ci_value']} expected_nak_value={summary['expected_nak_value']}",
            f"process_rc={summary['process_rc']} survived_window={summary['survived_window']}",
            f"frame_sha256={hashlib.sha256(frame).hexdigest()}",
        ]
        for fact in log_facts(RAW / f"{tag}-pppd.log"):
            lines.append(fact)
        lines.append("gdb_memory:")
        for line in gdb.splitlines():
            if "nak_buffer" in line or "ifname" in line or "the_channel" in line \
                    or "last_pkts_in" in line or "$1 =" in line:
                lines.append("  " + norm(line))
        text = "\n".join(lines) + "\n"
        (OUT / f"{tag}.txt").write_text(text)
        hashes.append((f"{tag}.txt", hashlib.sha256(text.encode()).hexdigest()))
    (OUT / "HASHES.txt").write_text(
        "".join(f"{h}  {name}\n" for name, h in hashes))


if __name__ == "__main__":
    main()
