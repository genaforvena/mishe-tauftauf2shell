set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-consumer-91.ff
set $encsp = encs
printf "HIT glyph=%d encs=%p\n", glyph, $encsp
watch *(long*)((char*)$encsp-8)
continue
delete 2
break fvimportbdf.c:1835
continue
printf "BEFORE MULT: encsp=%p mcnt=%d\n", $encsp, mcnt
printf "tcache counts[7]=%d entries[7]=%p\n", tcache->counts[7], tcache->entries[7]
printf "tcache counts[6]=%d entries[6]=%p\n", tcache->counts[6], tcache->entries[6]
printf "byte at encs user: "; x/2gx $encsp
next
printf "AFTER MULT: mult=%p\n", mult
printf "tcache counts[7]=%d entries[7]=%p\n", tcache->counts[7], tcache->entries[7]
quit
