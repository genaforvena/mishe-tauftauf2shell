# W195: pin the pointer the unmodified consumer ACTUALLY dereferences at
# exr_attr_list_destroy() attributes.c:305, not the secondary array that an
# earlier probe read via a guessed struct offset.  ASLR is explicitly ON:
# gdb's default disable-randomization is turned off here.
set pagination off
set confirm off
set disable-randomization off
show disable-randomization
break sort2_4ByteChannels_tiled
run
set $sinkbase = (long)outPtr
printf "SINK_OUT=%p\n", outPtr
break attributes.c:305
continue
printf "REAL_LIST=%p REAL_ENTRIES=%p SLOT0_ADDR=%p SLOT0=%p I=%d NUM=%d\n", list, list->entries, &list->entries[0], list->entries[0], i, list->num_attributes
printf "SLOT0_DELTA=%ld\n", (long)&list->entries[0] - $sinkbase
continue
printf "FAULT_R13=0x%016lx FAULT_PC=%p\n", $r13, $pc
x/2i $pc
