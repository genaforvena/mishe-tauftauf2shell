# W192: at entry to the pinned ZSTD sink, enumerate every live glibc tcache
# head relative to outPtr.  Caller supplies the sink breakpoint and `run -c`.
set pagination off
set confirm off
set $base = (long)outPtr
python
import gdb
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$base"))
t = int(gdb.parse_and_eval("tcache"))
def u16(a):
    return int.from_bytes(bytes(inf.read_memory(a, 2)), "little")
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
heads = []
for i in range(64):
    n = u16(t + 2 * i)
    e = u64(t + 128 + 8 * i)
    if n and e:
        heads.append((i, e - d, n))
print("TCACHE-HEADS=%s" % [(i, off, cnt) for i, off, cnt in heads if 0 <= off < 20000])
end
quit
