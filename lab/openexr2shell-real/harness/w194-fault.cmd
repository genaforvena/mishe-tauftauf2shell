# W194: caller stops at the pinned inverse-sort sink, then at the first
# exr_attr_list_destroy loop iteration (attributes.c:305).  Reports which
# entries[] slot the consumer is about to dereference, all live slots, and
# whether that slot is mapped in this process.  ASLR is explicitly ON:
# gdb's default disable-randomization is turned off here.
set pagination off
set confirm off
set disable-randomization off
show disable-randomization
break sort2_4ByteChannels_tiled
run
set $sinkbase = (long)outPtr
break attributes.c:305
continue
printf "LOOP i=%d entry=%p\n", i, list->entries[i]
python
import gdb
inf = gdb.selected_inferior()
lst = int(gdb.parse_and_eval("(long)list"))
n = int(gdb.parse_and_eval("list->num_attributes"))
entries = int.from_bytes(bytes(inf.read_memory(lst + 16, 8)), "little")
print("ENTRIES_DELTA=%d NUM=%d" % (entries - int(gdb.parse_and_eval("$sinkbase")), n))
for i in range(min(n, 12)):
    e = int.from_bytes(bytes(inf.read_memory(entries + 8 * i, 8)), "little")
    print("E[%d]=0x%016x" % (i, e))
end
x/3i $pc
x/gx 0x555555828210
