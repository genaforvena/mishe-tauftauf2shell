# W191: U=2N geometry (live tcache head at dst+4304). Dump the 2144-byte
# COPY2 destination exactly before the second inverse-sort memcpy.
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
    n = u16(t + 2*i)
    e = u64(t + 128 + 8*i)
    if n and e and d <= e < d + 10000:
        heads.append((i, e - d, e))
print("WINDOW_HEADS=%s" % heads)
if heads:
    gdb.execute("set $head = %d" % heads[0][2])
    print("NEXT-BEFORE-VAL=0x%016x" % u64(heads[0][2]))
    print("HEAD-ADDR=0x%016x" % heads[0][2])
end
break __memcpy_avx_unaligned_erms
continue
set $dst1 = (long)$rdi
printf "COPY1 dst-out=%+ld len=%ld\n", $dst1-$base, (long)$rdx
finish
dump binary memory work-w191/pre-copy2-u2n.bin $base+4288 $base+6432
continue
set $dst2 = (long)$rdi
printf "COPY2 dst-out=%+ld len=%ld\n", $dst2-$base, (long)$rdx
finish
continue
bt 10
printf "FINISHED\n"
quit
