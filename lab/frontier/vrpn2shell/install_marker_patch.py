#!/usr/bin/env python3
"""Install a lab-only benign-marker trampoline in a non-PIE vrpn_server copy.

The wire NUL changes the saved return address of handle_sender_message from
--ret to --target (a 256-byte-aligned function entry).  This patch replaces the
first five bytes at --target with `jmp cave`, where a stub distinguishes

  * normal entry: [rsp] is a return address inside .text -> execute the
    displaced `endbr64; push rbp` and jump to target+5;
  * corrupted return: [rsp] is stack-local data -> write a benign marker to
    stderr and jump back to --ret, resuming normal execution.

No source is modified.  This is a rung-4 lab mechanic, not a command-execution
claim: the marker bytes are installed by this script, and only the wire NUL
decides whether the redirected entry reaches them.
"""
import argparse
import hashlib
import re
import struct
import subprocess
from pathlib import Path

def p32(value):
    return struct.pack('<I', value & 0xFFFFFFFF)


def text_range(binary):
    out = subprocess.check_output(['readelf', '-SW', str(binary)], text=True)
    for line in out.splitlines():
        m = re.search(r'\[\s*\d+\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            addr, off, size = (int(x, 16) for x in m.groups())
            return addr, off, size
    raise SystemExit('no .text section')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src')
    ap.add_argument('dst')
    ap.add_argument('--target', required=True, type=lambda x: int(x, 16))
    ap.add_argument('--ret', required=True, type=lambda x: int(x, 16))
    ap.add_argument('--cave', required=True, type=lambda x: int(x, 16))
    args = ap.parse_args()
    src, dst = Path(args.src), Path(args.dst)
    data = bytearray(src.read_bytes())
    text_addr, text_off, text_size = text_range(src)
    text_end = text_addr + text_size
    if not (text_addr <= args.target < text_end and text_addr <= args.cave < text_end):
        raise SystemExit('address outside .text')
    if not (text_addr <= args.ret < text_end):
        raise SystemExit('return address outside .text')

    def filepos(addr):
        return text_off + addr - text_addr

    orig = bytes(data[filepos(args.target):filepos(args.target) + 5])
    if orig != bytes.fromhex('f30f1efa55'):
        raise SystemExit(f'unexpected prologue at target: {orig.hex()}')

    msg = b'VRPN2SHELL_MARKER\n'
    code = bytearray()
    code += bytes.fromhex('488b0424')          # mov rax,[rsp]
    code += b'\x48\x3d' + p32(text_addr)       # cmp rax,.text start
    in1 = len(code)
    code += b'\x73\x00'                        # jae in1
    low = len(code)
    code += b'\xeb\x00'                        # jmp redirected
    code[in1 + 1] = low - (in1 + 2)
    code += b'\x48\x3d' + p32(text_end)        # cmp rax,.text end
    inrange = len(code)
    code += b'\x72\x00'                        # jb normal
    high = len(code)
    code += b'\xeb\x00'                        # jmp redirected
    redirected = len(code)
    code[inrange + 1] = normal_placeholder = 0  # patched after layout
    code[high + 1] = redirected - (high + 2)
    # corrupted-return path: preserve caller-saved state across write(2,...)
    code += bytes.fromhex('5057565251'.replace(' ', ''))
    code += bytes.fromhex('4153')
    code += bytes.fromhex('b801000000 bf02000000')
    lea = len(code)
    code += b'\x48\x8d\x35' + p32(0)           # lea rsi,[rip+msg]
    code += b'\xba' + p32(len(msg))            # mov edx,len
    code += bytes.fromhex('0f05')              # syscall
    code += bytes.fromhex('415b59 5a5e5f58'.replace(' ', ''))
    jmpret = len(code)
    code += b'\xe9' + p32(0)                   # jmp ret
    normal = len(code)
    code[inrange + 1] = normal - (inrange + 2)
    code += orig                               # endbr64; push rbp
    jmptgt = len(code)
    code += b'\xe9' + p32(0)                   # jmp target+5
    msg_addr = args.cave + len(code)
    code[lea + 3:lea + 7] = p32(msg_addr - (args.cave + lea + 7))
    code[jmpret + 1:jmpret + 5] = p32(args.ret - (args.cave + jmpret + 5))
    code[jmptgt + 1:jmptgt + 5] = p32(args.target + 5 - (args.cave + jmptgt + 5))
    stub = bytes(code) + msg
    if len(stub) > 128:
        raise SystemExit(f'stub too long: {len(stub)}')

    data[filepos(args.target):filepos(args.target) + 5] = b'\xe9' + p32(args.cave - (args.target + 5))
    data[filepos(args.cave):filepos(args.cave) + len(stub)] = stub
    dst.write_bytes(data)
    dst.chmod(src.stat().st_mode & 0o777)
    print(f'src_sha256={hashlib.sha256(src.read_bytes()).hexdigest()}')
    print(f'dst_sha256={hashlib.sha256(dst.read_bytes()).hexdigest()}')
    print(f'text=[0x{text_addr:x},0x{text_end:x}) target=0x{args.target:x} '
          f'ret=0x{args.ret:x} cave=0x{args.cave:x} stub_len={len(stub)} '
          f'msg_addr=0x{msg_addr:x} displaced={orig.hex()}')


if __name__ == '__main__':
    main()
