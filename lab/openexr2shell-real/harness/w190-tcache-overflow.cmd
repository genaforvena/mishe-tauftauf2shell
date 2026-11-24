# W190: at entry to the pinned ZSTD sink, find a live glibc tcache user
# pointer in dst+0..dst+20000, then read its `next` word before and after the
# second inverse-sort memcpy.  Run with a sink breakpoint and `run -c FILE`
# supplied by the caller; all absolute addresses are normalized by the caller.
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
def safe64(a):
    try:
        return u64(a)
    except gdb.MemoryError:
        return 0
heads = []
for i in range(64):
    n = u16(t + 2*i)
    e = u64(t + 128 + 8*i)
    if n and e and d <= e < d + 20000:
        heads.append((i, e - d, e))
print("WINDOW_HEADS=%s" % [(i, off) for i, off, _ in heads])
if heads:
    gdb.execute("set $head = %d" % heads[0][2])
    print("NEXT-BEFORE-VAL=0x%016x" % u64(heads[0][2]))
    gdb.execute("set $headoff = %d" % heads[0][1])
    gdb.execute("set $headidx = %d" % heads[0][0])
else:
    gdb.execute("set $head = 0")
    gdb.execute("set $headoff = -1")
    gdb.execute("set $headidx = -1")
end
printf "TCACHE-WATCH idx=%ld off=%+ld ptr=%p\n", $headidx, $headoff, $head
printf "NEXT-BEFORE "
x/gx $head
break __memcpy_avx_unaligned_erms
continue
set $dst1 = (long)$rdi
set $len1 = (long)$rdx
printf "COPY1 dst-out=%+ld len=%ld\n", $dst1-$base, $len1
finish
continue
set $dst2 = (long)$rdi
set $len2 = (long)$rdx
printf "COPY2 dst-out=%+ld len=%ld\n", $dst2-$base, $len2
finish
printf "NEXT-AFTER "
x/gx $head
printf "NEXT-AFTER-VAL=0x%016lx\n", *(unsigned long long*)$head
continue
printf "FINISHED\n"
quit
