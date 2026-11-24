set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-pcf.ff
set $encsptr = encs
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
printf "HEADER BEFORE: prev_size=%p size=%p usable=%ld\n", *(void**)((char*)encs-16), *(void**)((char*)encs-8), malloc_usable_size(encs)
x/2gx (char*)encs-16
watch *(int*)((char*)encs-4)
continue
printf "WATCH HIT encs=%p store_addr=%p\n", encs, (char*)encs-4
printf "HEADER AFTER: prev_size=%p size=%p\n", *(void**)((char*)encs-16), *(void**)((char*)encs-8)
x/2gx (char*)encs-16
print/x encs[-1]
x/4xb &encs[-1]
delete 2
break free if $rdi == $encsptr
continue
printf "FREE CALL arg=%p (saved encs=%p)\n", $rdi, $encsptr
x/2gx (char*)$rdi-16
bt 4
continue
