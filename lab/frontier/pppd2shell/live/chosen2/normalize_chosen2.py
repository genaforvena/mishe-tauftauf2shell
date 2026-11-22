#!/usr/bin/env python3
"""Deterministic evidence for the W125 notifier-pointer experiment."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
OUT = ROOT / "chosen2" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)

TAGS = [
    "w125-ctrl-t1500",
    "w125-hook-pidchange",
    "w125-hook-t1840",
    "w125-hook-t1848",
    "w125-hook-t1856",
    "w125-asan-vuln",
    "w125-asan-fixed",
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


def main() -> None:
    hashes = []
    for tag in TAGS:
        summary = json.loads((RAW / f"{tag}-summary.json").read_text())
        gdb = (RAW / f"{tag}-gdb.txt").read_text(errors="replace")
        frame = (RAW / f"{tag}-frame.bin").read_bytes()
        lines = [
            f"=== {tag} ===",
            "binary=" + "/".join(Path(summary["binary"]).parts[-3:]),
            f"target_offset={summary['target_offset']}",
            f"pap_cis={summary['pap_cis']} async_cis={summary['async_cis']}",
            f"info_len={summary['info_len']} nak_bytes={summary['nak_bytes']}",
            f"ci_value={summary['ci_value']} expected_nak_value={summary['expected_nak_value']}",
            f"process_rc={summary['process_rc']} survived_window={summary['survived_window']}",
            f"frame_sha256={hashlib.sha256(frame).hexdigest()}",
        ]
        for tagline in (RAW / f"{tag}-pppd.log").read_text(
                errors="replace").splitlines():
            if any(k in tagline for k in (
                    "ERROR: AddressSanitizer", "WRITE of size", "#0 ",
                    "is located 0 bytes", "SUMMARY: AddressSanitizer",
                    "LCP: ignoring duplicate")):
                lines.append("asan/control: " + norm(tagline))
        lines.append("gdb_memory:")
        for line in gdb.splitlines():
            if any(k in line for k in (
                    "nak_buffer", "pidchange", "phasechange", "exitnotify",
                    "sigreceived", "fork_notifier", "the_channel", "$1 =")):
                # Only the leading gdb address is PIE-randomized; the value
                # after the colon is the deterministic readback.
                masked = re.sub(r"^0x[0-9a-f]{10,}", "0xADDR",
                                PID.sub("process PID", PATH.sub("BUILD/", line.rstrip())))
                lines.append("  " + masked)
        text = "\n".join(lines) + "\n"
        (OUT / f"{tag}.txt").write_text(text)
        hashes.append((f"{tag}.txt", hashlib.sha256(text.encode()).hexdigest()))
    (OUT / "HASHES.txt").write_text(
        "".join(f"{h}  {name}\n" for name, h in hashes))


if __name__ == "__main__":
    main()
