#!/usr/bin/env python3
"""Generate a driver from verbatim pinned SRS source ranges.

Every @@PLACEHOLDER@@ is replaced with bytes copied from pins/ under a #line
directive naming the pinned file, so ASan/UBSan frames carry upstream lines.
Harness-owned stubs live in driver_pre.cpp / driver_post.cpp only.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PINS = HERE / "pins"

# (pinned file, first line, last line, placeholder), inclusive, 1-based.
RANGES = {
    "vuln": [
        ("srs_kernel_rtc_rtcp.hpp", 46, 62, "@@HPP_STRUCT@@"),
        ("buffer.cpp.vuln", 91, 98, "@@BUF_REQUIRE@@"),
        ("buffer.cpp.vuln", 242, 249, "@@BUF_READ_BYTES@@"),
        ("buffer.cpp.vuln", 166, 178, "@@BUF_READ4@@"),
        ("rtcp.cpp.vuln", 53, 70, "@@DECODE_HEADER@@"),
        ("rtcp.cpp.vuln", 84, 98, "@@DECODE_COMMON@@"),
        ("rtcp.cpp.vuln", 802, 844, "@@DECODE_TWCC@@"),
    ],
    "fixed": [
        ("srs_kernel_rtc_rtcp.hpp", 46, 62, "@@HPP_STRUCT@@"),
        ("buffer.cpp.vuln", 91, 98, "@@BUF_REQUIRE@@"),
        ("buffer.cpp.vuln", 242, 249, "@@BUF_READ_BYTES@@"),
        ("buffer.cpp.vuln", 166, 178, "@@BUF_READ4@@"),
        ("rtcp.cpp.fixed", 53, 75, "@@DECODE_HEADER@@"),
        ("rtcp.cpp.fixed", 89, 106, "@@DECODE_COMMON@@"),
        ("rtcp.cpp.fixed", 811, 856, "@@DECODE_TWCC@@"),
    ],
}

src = (HERE / "driver_pre.cpp").read_text()
variant = sys.argv[1]
if variant not in RANGES:
    raise SystemExit(f"unknown variant {variant}")
for name, first, last, token in RANGES[variant]:
    lines = (PINS / name).read_text().splitlines()
    body = "\n".join(lines[first - 1:last])
    upstream = {"buffer.cpp.vuln": "srs_kernel_buffer.cpp",
                "rtcp.cpp.vuln": "srs_kernel_rtc_rtcp.cpp",
                "rtcp.cpp.fixed": "srs_kernel_rtc_rtcp.cpp",
                "srs_kernel_rtc_rtcp.hpp": "srs_kernel_rtc_rtcp.hpp"}
    quoted = upstream[name]
    src = src.replace(token, f'#line {first} "pinned/{quoted}"\n{body}\n#line 1 "harness"')
src += "\n" + (HERE / "driver_post.cpp").read_text()
Path(sys.argv[2]).write_text(src)
