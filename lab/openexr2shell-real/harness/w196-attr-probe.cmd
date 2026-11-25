# W196 precise probe: break at the switch in attr_destroy, inspect the
# file-chosen fake attribute, then stop at the chosen-pointer free site.
set pagination off
set confirm off
set disable-randomization on
break attributes.c:218
run
printf "ATTR=%p TYPE=%d STRPTR=%p\n", attr, attr->type, attr->string
x/4gx attr
x/3gx attr->string
break string.c:270
continue
printf "S=%p STR=%p ALLOC=%d LEN=%d\n", s, s->str, s->alloc_size, s->length
x/4gx s->str - 16
x/3i $pc
quit
