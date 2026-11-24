# W188: enumerate glibc tcache chunks live at entry to the pinned ZSTD sink.
# Run at the sort2_4ByteChannels_tiled breakpoint, e.g.
#   gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
#     -ex 'set disable-randomization on' \
#     -ex 'break sort2_4ByteChannels_tiled' -ex 'run -c FILE' \
#     -x harness/tcache-reach.cmd build-vuln-plain/bin/exrcheck
# "hits" lists (chain index, offset from outPtr) for every tcache user pointer
# inside the 384-byte copy window (dst+0 .. dst+384).  Absolute addresses are
# normalized away; only offsets relative to the destination are printed.
delete 1
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
def safe64(a):
    try:
        return u64(a)
    except gdb.MemoryError:
        return 0
print("BASE=0x%x tcache=0x%x" % (d, t))
for i in range(64):
    n = u16(t + 2*i)                 # counts[64], uint16 each
    e = u64(t + 128 + 8*i)           # entries[64], pointer each
    if n or e:
        hits = []
        cur = e
        for j in range(min(n, 8)):
            if not cur:
                break
            if d <= cur < d + 384:
                hits.append((j, cur - d))
            cur = (cur >> 12) ^ safe64(cur)   # glibc 2.39 PROTECT_PTR
        print("TCACHE idx=%d size=0x%x n=%d head_off=%s hits=%s"
              % (i, 0x20 + 0x10*i, n,
                 ("%+d" % (e - d)) if e else "nil", hits))
end
continue
printf "FINISHED\n"
quit
