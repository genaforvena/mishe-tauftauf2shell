#!/usr/bin/env python3
"""Generate a differential driver from verbatim pinned memcached source ranges.

No memcached logic is retyped: every crawler.c block is copied byte-for-byte
from pins/ with a #line directive so ASan reports the pinned line numbers.
Harness-owned stubs live in driver_pre.c, driver_mid.c and driver_post.c.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PINS = HERE / "pins"


def block(lines, start, end):
    return "".join(lines[start - 1:end])


def generate(variant):
    srcname = f"crawler.c.{variant}"
    lines = (PINS / srcname).read_text().splitlines(keepends=True)
    if variant == "vuln":
        write_range = (452, 507)
        set_client_range = (816, 833)
    else:
        write_range = (452, 519)
        set_client_range = (828, 845)

    ranges_a = [
        (28, 34),            # crawler_client_t: buflen, bufused, buf
        (36, 58),            # crawler_module_t / module regs
    ]
    ranges_b = [
        (128, 128),          # LRU_CRAWLER_MINBUFSPACE 8192
        (273, 280),          # KADD / KSP append macros
        (282, 372),          # crawler_metadump_eval: append at buf + bufused
        write_range,         # lru_crawler_write: vulnerable or fixed
        set_client_range,    # lru_crawler_set_client: malloc(8192*16)
    ]

    def emit(target, start, end):
        target.append(f'#line {start} "{srcname}"\n')
        target.append(block(lines, start, end))
        if not target[-1].endswith("\n"):
            target.append("\n")
        target.append("\n")

    out = [(HERE / "driver_pre.c").read_text(), "\n"]
    for start, end in ranges_a:
        emit(out, start, end)
    out.append('#line 1 "driver_mid.c"\n')
    out.append((HERE / "driver_mid.c").read_text())
    out.append("\n")
    for start, end in ranges_b:
        emit(out, start, end)
    out.append('#line 1 "driver_post.c"\n')
    out.append((HERE / "driver_post.c").read_text())

    target = HERE / "out" / f"driver_{variant}.c"
    target.parent.mkdir(exist_ok=True)
    target.write_text("".join(out))
    print(target)


if __name__ == "__main__":
    for variant in sys.argv[1:] or ["vuln", "fixed"]:
        generate(variant)
