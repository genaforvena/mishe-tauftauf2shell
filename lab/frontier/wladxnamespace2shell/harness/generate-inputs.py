#!/usr/bin/env python3
"""Deterministic inputs for the WLA DX wlalink namespace overflow."""
from pathlib import Path

HDR = (
    ".MEMORYMAP\n"
    "DEFAULTSLOT 0\n"
    "SLOT 0 $0000 $4000\n"
    ".ENDME\n"
    ".ROMBANKSIZE $4000\n"
    ".ROMBANKS 2\n"
)

def src(ns: str) -> str:
    return HDR + f'.SECTION "S" NAMESPACE "{ns}" FREE\n.db $43\n.ENDS\n'

p = Path(__file__).resolve().parent
inputs = {
    "attack.s": src("C" * 270),
    "attack-large.s": src("C" * 2044),
    "attack-pattern.s": src("A" * 256 + "D" * 14),
    "safe.s": src("ok"),
    "linkfile": "[objects]\nattack.o\n",
    "linkfile-large": "[objects]\nattack-large.o\n",
    "linkfile-pattern": "[objects]\nattack-pattern.o\n",
    "linkfile-pattern-fixed": "[objects]\nattack-pattern-fixed.o\n",
    "linkfile-safe": "[objects]\nsafe.o\n",
    "linkfile-safe-fixed": "[objects]\nsafe-fixed.o\n",
}
for name, text in inputs.items():
    (p / name).write_text(text)
print("GENERATE_INPUTS_OK")
