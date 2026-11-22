#!/usr/bin/env python3
"""Deterministic evidence for the W132 controlled-callback experiment."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
OUT = ROOT / "call" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)

TAGS = [
    "w132a1",        # vulnerable pin, unlink@plt callback
    "w132s1",        # same with strace
    "w132s2",        # straced attack replay
    "w132c-safe",    # short safe ConfReq, no overflow
    "w132c-null",    # NULL callback control
    "w132c-fixed",   # fixed 2.5.4 pin, same frames
]

PID = re.compile(r"^\d+ ")
BUILD = re.compile(r"/home/[^/]+/[^/]+/")


def norm(line: str) -> str:
    line = BUILD.sub("", line.rstrip())
    line = PID.sub("PID ", line)
    return re.sub(r"\b\d{5,}\b", "PID", line)


def main() -> None:
    hashes = []
    for tag in TAGS:
        summary = json.loads((RAW / f"{tag}-summary.json").read_text())
        frame = (RAW / f"{tag}-nak.bin").read_bytes()
        rej_path = RAW / f"{tag}-rej.bin"
        rej = rej_path.read_bytes() if rej_path.exists() else b""
        rej_norm = re.sub(rb"/tmp/pppd2shell-r5-[A-Za-z0-9_-]+-victim",
                          b"/tmp/MARKER", rej)
        rej_norm = rej_norm[:-3]   # FCS and closing flag depend on the marker
        lines = [
            "=== W132 ===",
            "binary=" + "/".join(Path(summary["binary"]).parts[-3:]),
            f"mode={summary['mode']}",
            f"callback={summary['callback']}",
            f"side_effect_observed={summary['side_effect_observed']}",
            f"victim_content_after={summary['victim_content_after']!r}",
            f"process_rc={summary['process_rc']}",
            "nak_sha256=" + hashlib.sha256(frame).hexdigest(),
            "rej_norm_sha256=" + hashlib.sha256(rej_norm).hexdigest(),
        ]
        for key in ("sigreceived", "notifier_ptr", "path_ptr"):
            if key in summary.get("pointers", {}):
                lines.append(f"{key}={summary['pointers'][key]}")
        strace = RAW / f"{tag}-strace.log"
        if strace.exists():
            for line in strace.read_text(errors="replace").splitlines():
                if "unlink(" in line:
                    lines.append("strace: " + re.sub(
                        r"/tmp/pppd2shell-r5-[A-Za-z0-9_-]+-victim",
                        "/tmp/MARKER", norm(line)))
        for line in (RAW / f"{tag}-pppd.log").read_text(
                errors="replace").splitlines():
            if any(k in line for k in (
                    "LCP: ignoring duplicate", "Fatal signal 11",
                    "Connection terminated", "Child process")):
                lines.append("pppd: " + norm(line))
        gdb = RAW / f"{tag}-pre-signal-gdb.txt"
        if gdb.exists():
            for line in gdb.read_text(errors="replace").splitlines():
                if any(k in line for k in (
                        "<sigreceived>", "<inpacket_buf", "Cannot attach")):
                    lines.append("gdb: " + norm(line))
        text = "\n".join(lines) + "\n"
        (OUT / f"{tag}.txt").write_text(text)
        hashes.append((f"{tag}.txt", hashlib.sha256(text.encode()).hexdigest()))
    (OUT / "HASHES.txt").write_text(
        "".join(f"{h}  {name}\n" for name, h in hashes))


if __name__ == "__main__":
    main()
