# W196: measure live heap addresses with ASLR OFF in the debuggee, so a
# file can carry a chosen pointer to a file-chosen fake exr_attribute_t.
set pagination off
set confirm off
set disable-randomization on
show disable-randomization
break sort2_4ByteChannels_tiled
run
printf "SINK_OUT=%p SINK_IN=%p\n", outPtr, inPtr
break attributes.c:305
continue
printf "REAL_LIST=%p REAL_ENTRIES=%p SLOT0_ADDR=%p SLOT0=%p I=%d NUM=%d\n", list, list->entries, &list->entries[0], list->entries[0], i, list->num_attributes
printf "SLOT0_DELTA=%ld\n", (long)&list->entries[0] - (long)outPtr
x/2i $pc
quit
