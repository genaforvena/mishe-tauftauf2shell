# Map the real 4096-byte sink's destination range onto live glibc chunks.
# Run from lab/openexr2shell-real:
#   gdb -q -batch -x harness/heap-victims.cmd bin-vuln-plain/flat_harness
# Break on memcpy when the length is the advisory's 4096-byte copy; a source
# breakpoint at internal_zstd.c:472 resolves to :474 and never hits.
# gdb disables inferior ASLR by default; pin it so residue pointer bytes
# stay byte-stable across runs.
set disable-randomization on
set pagination off
set confirm off
set print pretty off
break memcpy if $rdx == 4096
run cases/poc.exr
python
import gdb
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$rdi"))
s = int(gdb.parse_and_eval("$rsi"))
n = int(gdb.parse_and_eval("$rdx"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
print("SINK n=%d src_minus_dst=%d" % (n, s - d))
base = (d - 16) & ~15
chunks = []
while base < d + n:
    word = u64(base + 8)
    size = word & ~0xf
    if size < 32 or size > (1 << 30):
        print("BAD-CHUNK off=%+d" % (base - d))
        break
    chunks.append([base, size, word])
    base += size
print("CHUNK-COUNT total=%d first_off=%d" %
      (len(chunks), chunks[1][0] - d if len(chunks) > 1 else -1))
f = gdb.newest_frame()
decode_val = None
while f is not None:
    if (f.name() or "") == "main":
        try: decode_val = f.read_var("decode")
        except Exception: pass
        break
    f = f.older()
ptrs = []
def scan(val, name, depth):
    if depth > 2: return
    t = val.type.strip_typedefs()
    if t.code == gdb.TYPE_CODE_PTR:
        try: a = int(val)
        except Exception: return
        if a: ptrs.append((name, a))
    elif t.code == gdb.TYPE_CODE_STRUCT:
        for fld in t.fields():
            if not fld.name: continue
            try: scan(val[fld.name], name + "." + fld.name, depth + 1)
            except Exception: pass
if decode_val is not None:
    scan(decode_val, "decode", 0)
inside = sorted([(a - d, nm) for (nm, a) in ptrs if d <= a < d + n])
print("LIVE-PTR-COUNT scanned=%d inside=%d" % (len(ptrs), len(inside)))
for (off, nm) in inside:
    print("LIVE-PTR-INSIDE %s off=%+d" % (nm, off))
gdb.execute("finish", to_string=True)
bad = 0
for (b, sz, old) in chunks:
    new = u64(b + 8)
    if new != old: bad += 1
    print("CHUNK off=%+d size=0x%x hdr_before=0x%x hdr_after=0x%x %s" %
          (b - d, sz, old, new, "CHANGED" if new != old else "same"))
first = chunks[1]
print("HDR-CORRUPTED %d/%d" % (bad, len(chunks)))
print("FIRST-HDR off=%+d before=0x%x after-changed=%s" %
      (first[0] - d, first[2], "yes" if u64(first[0] + 8) != first[2] else "no"))
print("END-PY")
end
quit
