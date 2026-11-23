#!/usr/bin/env python3
"""Assert the W177 byte-granularity measurements saved in EVIDENCE_DIR.

Usage: python3 .../check_byte_granularity.py EVIDENCE_DIR

The four logs come from measure_byte_granularity.py on the pinned plain
Release v1.23.6 build. The checker does not rebuild anything; it verifies the
observed OOB source rows and the negative pre-compensation result.
"""
import re
import sys
from pathlib import Path

EXPECT = {
    'uniform-gdb.out': '80' * 64,
    'blocks-gdb.out': ('10' * 8 + '22' * 8 + '32' * 8 + '44' * 8 +
                       '54' * 8 + '66' * 8 + '76' * 8 + '88' * 8),
}
PRECOMP_TARGET = 'deadbeef41424344'


def source_row(path: Path) -> str:
    text = path.read_text()
    if 'OOB dest_off=32768' not in text:
        raise SystemExit(f'{path.name}: no first OOB row')
    if 'frame 1 decoded: 64x72 stride=64' not in text:
        raise SystemExit(f'{path.name}: frame 1 not decoded 64x72')
    tail = text[text.find('OOB dest_off='):]
    lines = re.findall(r'^0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s+){7}0x[0-9a-f]{2})\s*$',
                       tail, re.M)
    if len(lines) < 8:
        raise SystemExit(f'{path.name}: source dump incomplete')
    return ''.join(f'{int(v, 16):02x}' for line in lines[:8] for v in line.split())


def main() -> None:
    d = Path(sys.argv[1])
    ok = 0
    for name, expected in EXPECT.items():
        got = source_row(d / name)
        if got != expected:
            raise SystemExit(f'{name}: expected {expected}, got {got}')
        print(f'PASS {name}: OOB source row {got}')
    first = source_row(d / 'precomp-it01-gdb.out')[48:64]
    last = source_row(d / 'precomp-it19-gdb.out')[48:64]
    if first != 'dbb0beec463e4443':
        raise SystemExit(f'precomp it01: expected dbb0beec463e4443, got {first}')
    if last == PRECOMP_TARGET:
        raise SystemExit('precomp it19 unexpectedly reached the target')
    print(f'PASS precomp-it01-gdb.out: got {first}, target {PRECOMP_TARGET}')
    print(f'PASS precomp-it19-gdb.out: got {last}, still not {PRECOMP_TARGET}')
    print(f'PASS={ok + 2} FAIL=0')


if __name__ == '__main__':
    main()
