set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-size-91.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
x/2gx (char*)encs-16
watch *(long*)((char*)encs-8)
continue
printf "AFTER WRITE encs=%p\n", encs
x/gx (char*)encs-8
x/8xb (char*)encs-8
break fvimportbdf.c:1770
continue
printf "AT FREE encs=%p\n", encs
x/gx (char*)encs-8
set $e = encs
break __libc_free if $rdi == $e
continue
printf "IN FREE arg=%p\n", $rdi
finish
printf "AFTER FREE tcache[7]=%p encs=%p\n", tcache->entries[7], $e
continue
quit
