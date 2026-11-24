# W192: at entry to the pinned ZSTD sink, find the live tcache head in the
# COPY2 window, dump the destination bytes just before COPY2, and read the
# head's `next` word before and after COPY2.  Caller supplies the breakpoint,
# `run -c FILE` and a `set $dumpfile`/`set $n` pair via -ex flags.
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
    if n and e and d <= e < d + 20000:
        heads.append((i, e - d, e))
print("WINDOW_HEADS=%s" % [(i, off) for i, off, _ in heads])
gdb.execute("set $head = %d" % (heads[0][2] if heads else 0))
gdb.execute("set $headoff = %d" % (heads[0][1] if heads else -1))
gdb.execute("set $headidx = %d" % (heads[0][0] if heads else -1))
end
printf "TCACHE-WATCH idx=%ld off=%+ld ptr=%p\n", $headidx, $headoff, $head
break __memcpy_avx_unaligned_erms
continue
set $dst1 = (long)$rdi
printf "COPY1 dst-out=%+ld len=%ld\n", $dst1-$base, (long)$rdx
finish
continue
set $dst2 = (long)$rdi
set $len2 = (long)$rdx
printf "COPY2 dst-out=%+ld len=%ld\n", $dst2-$base, $len2
python
import gdb
dst = int(gdb.parse_and_eval("$dst2"))
ln = int(gdb.parse_and_eval("$len2"))
path = gdb.parse_and_eval("$dumpfile").string()
data = bytes(gdb.selected_inferior().read_memory(dst, ln))
open(path, "wb").write(data)
print("DUMPED=%d" % ln)
end
printf "NEXT-BEFORE-VAL=0x%016lx\n", *(unsigned long long*)$head
finish
printf "NEXT-AFTER-VAL=0x%016lx\n", *(unsigned long long*)$head
continue
printf "FINISHED\n"
quit
