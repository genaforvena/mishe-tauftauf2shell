# W196: ASLR OFF in the debuggee so the file-carried fake attribute address
# is mapped.  Verify entries[0] is the file-chosen fake attribute, that
# attr_destroy's switch reads the file-chosen type, and that
# exr_attr_string_destroy receives a file-chosen str pointer and reads
# file-chosen bytes there.
set pagination off
set confirm off
set disable-randomization on
show disable-randomization
break attributes.c:305
run
printf "SLOT0=%p NUM=%d I=%d\n", list->entries[0], list->num_attributes, i
break exr_attr_string_destroy
continue
printf "STR=%p ALLOC=%d LEN=%d\n", s->str, s->alloc_size, s->length
x/4gx s->str - 16
x/3i $pc
continue
printf "END_PC=%p\n", $pc
quit
