#!/usr/bin/env python3
"""Deterministic evidence for the W133 dlopen / wire-command experiment."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
OUT = ROOT / "call" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)

TAGS = [
    "w133d",     # vulnerable pin, dlopen@plt, wire-carried command
    "w133e",     # straced replay of the same attack
    "w133f",     # fixed 2.5.4 pin, identical frames
    "w133n",     # NULL callback control
    "w133s",     # short safe ConfReq control
]

MARKER = re.compile(r"/tmp/pppd2shell-r5-[A-Za-z0-9_-]+-(victim|payload\.so)")
PID = re.compile(r"^\d+ ")
BUILD = re.compile(r"/home/[^/]+/[^/]+/")
LONGNUM = re.compile(r"\b\d{5,}\b")
HEXADDR = re.compile(r"0x[0-9a-fA-F]{8,}")


def norm(line: str) -> str:
    line = MARKER.sub(r"/tmp/MARKER-\1", line.rstrip())
    line = BUILD.sub("", line)
    line = PID.sub("PID ", line)
    line = LONGNUM.sub("PID", line)
    return HEXADDR.sub("0xADDR", line)


def main() -> None:
    hashes = []
    for tag in TAGS:
        summary = json.loads((RAW / f"{tag}-summary.json").read_text())
        frame = (RAW / f"{tag}-nak.bin").read_bytes()
        rej_path = RAW / f"{tag}-rej.bin"
        rej = rej_path.read_bytes() if rej_path.exists() else b""
        rej_norm = re.sub(
            rb"/tmp/pppd2shell-r5-[A-Za-z0-9_-]+-(?:victim|payload\.so)",
            b"/tmp/MARKER", rej)
        rej_norm = rej_norm[:rej_norm.find(b"PPPD2SHELL_W133_WIRE_COMMAND_RAN")
                            + len(b"PPPD2SHELL_W133_WIRE_COMMAND_RAN")]
        lines = [
            "=== W133 dlopen wire command ===",
            "binary=" + "/".join(Path(summary["binary"]).parts[-3:]),
            f"mode={summary['mode']}",
            f"callback={summary['callback']}",
            f"signal={summary['signal']}",
            f"expect={summary['expect']}",
            f"side_effect_observed={summary['side_effect_observed']}",
            f"victim_content_after={summary['victim_content_after']!r}",
            f"process_rc={summary['process_rc']}",
            "nak_sha256=" + hashlib.sha256(frame).hexdigest(),
            "rej_norm_sha256=" + hashlib.sha256(rej_norm).hexdigest(),
        ]
        layout = summary.get("layout", {})
        for key in ("callback", "path", "wire_cmd", "cmd_ptr", "path_ptr",
                    "notifier_ptr", "sigreceived_offset"):
            if key in layout:
                lines.append(f"layout.{key}=" + norm(str(layout[key])))
        for key, value in summary.get("pointers", {}).items():
            lines.append(f"{key}={value}")
        strace = RAW / f"{tag}-strace.log"
        if strace.exists():
            for line in strace.read_text(errors="replace").splitlines():
                if any(k in line for k in (
                        "SIGINT", "payload.so", 'execve("/bin/sh"',
                        "-victim")):
                    lines.append("strace: " + norm(line))
        for line in (RAW / f"{tag}-pppd.log").read_text(
                errors="replace").splitlines():
            if any(k in line for k in (
                    "LCP: ignoring duplicate", "Terminating on signal",
                    "Fatal signal")):
                lines.append("pppd: " + norm(line))
        text = "\n".join(lines) + "\n"
        (OUT / f"{tag}.txt").write_text(text)
        hashes.append((f"{tag}.txt", hashlib.sha256(text.encode()).hexdigest()))
    (OUT / "HASHES_DLOPEN.txt").write_text(
        "".join(f"{h}  {name}\n" for name, h in hashes))


if __name__ == "__main__":
    main()
