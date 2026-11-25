#!/bin/sh
# W198: two bounded negatives about extending W197 toward an ASLR-on or
# command-execution grade.  Neither changes the grade; both are preserved so
# a later wake does not spend time on the same two ideas.
#
#  (1) A partial overwrite of a live pointer at the COPY2 window tail cannot
#      work in the W197 geometry: the last 32 bytes of the chosen window and
#      the bytes past it are all zero, not a code pointer.  The low 12 bits of
#      a code pointer are ASLR-invariant, but there is no live pointer at the
#      boundary to partially overwrite.
#  (2) The pinned exrcheck imports no system/popen/exec, and the system libc
#      has no `mov %rsi,%rdi` whose next 12 bytes jmp or call system().  The
#      opaque destructor's (ctxt, chosen_ptr, chosen_int) argument shape thus
#      has no one-gadget route to a benign command in these pinned builds.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

test "$(sha256sum cases/p197-chosen-ip.exr | cut -d' ' -f1)" = \
    c75957f1e36ae3e03df6e79aaf5070164e0f2afe081c44bbd59542c0c16ec45a
test "$(sha256sum harness/w198-tail.cmd | cut -d' ' -f1)" = \
    5fcce088dca714e167f29890fcc9f4ad71e836cde0a06144532b68e8e27cf851

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

gdb -q -batch -ex 'set args -c cases/p197-chosen-ip.exr' \
    -x harness/w198-tail.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true

awk '/=== TAIL_WORDS ===/{f=1;next} f && /^0x555555828/{print}' \
    "$RAW" > evidence/w198-tail.out
test "$(wc -l < evidence/w198-tail.out)" -eq 9
awk '{ if ($2 != "0x0000000000000000" || $3 != "0x0000000000000000") bad=1 }
     END { exit bad+0 }' evidence/w198-tail.out

python3 - <<'PY' > evidence/w198-gadgets.out
import re, struct, subprocess
binp = 'build-vuln-plain/bin/exrcheck'
syms = subprocess.run(['nm', '-D', '--defined-only', binp],
                      capture_output=True, text=True).stdout
bin_system = len([l for l in syms.splitlines()
                  if re.search(r'\b(system|popen|exec[lv]p?e?)@@?', l)])
libc = None
for line in subprocess.run(['ldd', binp], capture_output=True,
                           text=True).stdout.splitlines():
    m = re.search(r'(/[^ ]*libc\.so\.6)', line)
    if m:
        libc = m.group(1)
        break
assert libc, 'no libc path from ldd'
nm = subprocess.run(['nm', '-D', '--defined-only', libc],
                    capture_output=True, text=True).stdout
m = re.search(r'^([0-9a-f]+)\s+W\s+system@@', nm, re.M)
assert m, 'no system symbol in libc'
system = int(m.group(1), 16)
data = open(libc, 'rb').read()
phoff = struct.unpack_from('<Q', data, 0x20)[0]
phentsize = struct.unpack_from('<H', data, 0x36)[0]
phnum = struct.unpack_from('<H', data, 0x38)[0]
offset = vaddr = size = None
for i in range(phnum):
    p = phoff + i * phentsize
    p_type, p_flags = struct.unpack_from('<II', data, p)
    if p_type == 1 and (p_flags & 1):  # PT_LOAD, PF_X
        offset, vaddr, _, size, _, _ = struct.unpack_from('<QQQQQQ', data, p + 8)
        break
assert vaddr is not None, 'no PT_LOAD PF_X segment'
seg = data[offset:offset + size]
hits = 0
pos = 0
while True:
    p = seg.find(b'\x48\x89\xf7', pos)  # mov %rsi,%rdi
    if p < 0:
        break
    for k in range(13):
        q = p + 3 + k
        if q + 5 <= len(seg) and seg[q] in (0xe9, 0xe8):
            rel = struct.unpack('<i', seg[q + 1:q + 5])[0]
            if vaddr + q + 5 + rel == system:
                hits += 1
    pos = p + 1
print(f'BIN_SYSTEM_LIKE_IMPORTS={bin_system}')
print(f'LIBC={libc}')
print(f'LIBC_SYSTEM_OFFSET=0x{system:x}')
print(f'EXEC_SEG=0x{vaddr:x}+0x{size:x}')
print(f'MOV_RSI_RDI_TO_SYSTEM_GADGETS={hits}')
PY

grep -q '^BIN_SYSTEM_LIKE_IMPORTS=0$' evidence/w198-gadgets.out
grep -q '^MOV_RSI_RDI_TO_SYSTEM_GADGETS=0$' evidence/w198-gadgets.out

printf 'RESULT PASS\n'
sha256sum evidence/w198-tail.out evidence/w198-gadgets.out
