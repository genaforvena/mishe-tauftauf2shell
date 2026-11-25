# W196: pin the chosen pointer at the free() call made by
# exr_attr_string_destroy() for the file-chosen fake attribute.
set pagination off
set confirm off
set disable-randomization on
break attributes.c:218
run
printf "ATTR=%p TYPE=%d STRPTR=%p\n", attr, attr->type, attr->string
break free
continue
printf "FREE_RDI=%p\n", $rdi
x/2gx $rdi - 16
x/3i $pc
continue
printf "END_PC=%p\n", $pc
quit
