# W189: like tcache-reach.cmd but preserves breakpoint 1 so `ignore 1 N` can
# select a later decode in a multi-file `exrcheck -c` invocation. Run with
#   gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
#     -ex 'set disable-randomization on' \
#     -ex 'break sort2_4ByteChannels_tiled' -ex 'ignore 1 1' \
#     -ex 'run -c BASE POC' -x harness/tcache-reach2.cmd BIN
# hits lists (chain index, offset from outPtr) for tcache user pointers in
# dst+0..dst+384; absolute addresses are normalized away.
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
    n = u16(t + 2*i)
    e = u64(t + 128 + 8*i)
    if n or e:
        hits = []
        cur = e
        for j in range(min(n, 8)):
            if not cur:
                break
            if d <= cur < d + 384:
                hits.append((j, cur - d))
            cur = (cur >> 12) ^ safe64(cur)
        print("TCACHE idx=%d size=0x%x n=%d head_off=%s hits=%s"
              % (i, 0x20 + 0x10*i, n,
                 ("%+d" % (e - d)) if e else "nil", hits))
end
continue
printf "FINISHED\n"
quit
