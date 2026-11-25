#!/usr/bin/env python3
"""W200: bound the W197 indirect-call route as a benign-command gadget.

At pinned opaque.c:79 the file-chosen call target receives
(rdi=ctxt, rsi=file-chosen pointer, rdx=file-chosen int).  A one-gadget
command route therefore needs either (a) a loaded module that imports/calls
system, popen or exec*, with rsi moved into rdi before the call, or (b) a
short gadget that moves rsi into rdi and reaches an execve syscall or an
indirect call through an attacker-controlled register.

Prints a normalized report; the shell harness hashes it and asserts the
command-launch classes are empty.  Bounded by a fixed eight-instruction
lookahead and by the modules the pinned exrcheck actually loads.
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

LAB = Path(sys.argv[1]).resolve()
EXRCHECK = LAB / "build-vuln-plain/bin/exrcheck"
LOOKAHEAD = 8
COMMAND = re.compile(
    r"\b(system|__libc_system|popen|execve|execv|execvp|execveat|execl|"
    r"execlp|execle|posix_spawn|posix_spawnp)(?:@@|\@|$)"
)
LINE = re.compile(r"^\s*([0-9a-f]+):\s+(.*?)\s*$")
RSI_RDI = re.compile(r"\b(mov|xchg)\s+%rsi,%rdi\b")


def modules():
    out = subprocess.run(["ldd", str(EXRCHECK)], capture_output=True,
                         text=True, check=True).stdout
    paths = []
    for line in out.splitlines():
        m = re.search(r"=>\s+(/\S+)", line)
        if m and Path(m.group(1)).exists():
            paths.append(Path(m.group(1)))
    return sorted(set(paths))


def parse(path):
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(path)],
                         capture_output=True, text=True, check=True).stdout
    ins = []
    for line in dis.splitlines():
        m = LINE.match(line)
        if m:
            ins.append((int(m.group(1), 16), m.group(2)))
    return ins


def main():
    print(f"exrcheck={EXRCHECK.relative_to(LAB)}")
    mods = modules()
    print("modules=" + ",".join(p.name for p in mods))
    for p in mods:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"module_sha256 {p.name} {h}")
    print(f"lookahead={LOOKAHEAD}")
    total_ins = 0
    imports = []
    branches = []
    syscalls = []
    indirect = []
    shaped = []
    for p in mods:
        ins = parse(p)
        total_ins += len(ins)
        dyn = subprocess.run(["nm", "-D", str(p)], capture_output=True,
                             text=True).stdout
        for line in dyn.splitlines():
            m = re.search(r"\bU\s+([\w@.$]+)", line)
            if m and COMMAND.search(m.group(1)):
                imports.append(f"{p.name}:{m.group(1)}")
        for i, (addr, text) in enumerate(ins):
            if re.search(r"\b(call|jmp)\b", text) and COMMAND.search(text):
                branches.append(f"{p.name}:{addr:x}:{text}")
            if not RSI_RDI.search(text):
                continue
            window = ins[i + 1:i + 1 + LOOKAHEAD]
            texts = [t for _, t in window]
            if any(re.search(r"\b(call|jmp)\b", t) and COMMAND.search(t)
                   for t in texts):
                shaped.append(f"{p.name}:{addr:x}")
            if any(re.search(r"\bsyscall\b", t) for t in texts):
                rax = []
                for _, t in window:
                    r = re.search(r"mov\s+\$(0x[0-9a-f]+|[0-9]+),%eax", t)
                    if r:
                        rax.append(r.group(1))
                syscalls.append(f"{p.name}:{addr:x}:rax={','.join(rax) or 'none'}")
            for _, t in window:
                m = re.search(r"call\s+\*([^#]+)", t)
                if m:
                    indirect.append(f"{p.name}:{addr:x}:{m.group(1).strip()}")
    print(f"instructions={total_ins}")
    print(f"command_imports={len(imports)} " + " ".join(imports))
    print(f"direct_command_branches={len(branches)} " + " ".join(branches))
    print(f"rsi_to_rdi_then_command_branch={len(shaped)} " + " ".join(shaped))
    print(f"execve_immediate_in_windows="
          f"{sum(1 for s in syscalls if 'rax=0x3b' in s or 'rax=59' in s)}")
    print(f"rsi_to_rdi_then_indirect_call={len(indirect)} " + " ".join(indirect))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
