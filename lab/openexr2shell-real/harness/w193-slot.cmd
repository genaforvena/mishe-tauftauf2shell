# W193: caller stops at the pinned inverse-sort sink with
# `break sort2_4ByteChannels_tiled` and `run -c FILE`.  Report the live
# exr_attribute_list_t entries array offset relative to outPtr and its
# pointer slots.  ASLR is left enabled; the chosen slot values come from
# the file, not from the (normalized) heap base.
set pagination off
set confirm off
set $base = (long)outPtr
break exr_attr_list_destroy if list->num_attributes > 0
continue
python
import gdb
inf = gdb.selected_inferior()
base = int(gdb.parse_and_eval("$base"))
lst = int(gdb.parse_and_eval("(long)list"))
entries = int.from_bytes(bytes(inf.read_memory(lst + 16, 8)), "little")
num = int(gdb.parse_and_eval("list->num_attributes"))
print("ENTRIES_DELTA=%d NUM=%d" % (entries - base, num))
for i in range(min(num, 12)):
    e = int.from_bytes(bytes(inf.read_memory(entries + 8 * i, 8)), "little")
    print("E[%d]=0x%016x" % (i, e))
end
quit
