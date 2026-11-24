# Reduced-length sink observation. Run from lab/openexr2shell-real:
#   gdb -q -batch -ex 'set $copy_len = 264' -x harness/partial-length.cmd \
#       --args ./bin-vuln-plain/flat_harness work-partial/poc-s66.exr
# The copy length is set by -ex so one script serves both boundary cases.
set disable-randomization on
set pagination off
set confirm off
set print pretty off
break memcpy if $rdx == $copy_len
run
python
import gdb
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$rdi"))
s = int(gdb.parse_and_eval("$rsi"))
n = int(gdb.parse_and_eval("$rdx"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
print("SINK n=%d src_minus_dst=%d" % (n, s - d))
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
print("BEFORE dst+272=0x%x dst+304=0x%x" % (u64(d + 272), u64(d + 304)))
gdb.execute("finish", to_string=True)
print("AFTER  dst+272=0x%x dst+304=0x%x" % (u64(d + 272), u64(d + 304)))
print("END-PY")
end
quit
