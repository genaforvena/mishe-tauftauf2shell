#!/usr/bin/env python3
"""Regenerate the pinned services-file inputs for parse_services() runs."""
from pathlib import Path

out = Path(__file__).resolve().parent / "inputs"
out.mkdir(exist_ok=True)
(out / "digits20.services").write_bytes(b"1" * 20 + b"/tcp\n")
(out / "digits11.services").write_bytes(b"2" * 11 + b"/tcp\n")
(out / "safe5.services").write_bytes(b"12345/tcp\n")
(out / "safe9.services").write_bytes(b"123456789/udp\n")
