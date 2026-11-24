set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-consumer-91.ff
set $encsp = encs
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, $encsp
x/2gx $encsp-16
watch *(long*)((char*)$encsp-8)
continue
printf "AFTER WRITE sizeword:\n"
x/2gx $encsp-16
delete 2
break fvimportbdf.c:1835
continue
printf "BEFORE MULT CALLOC encsp=%p mcnt=%d sf->glyphcnt=%d\n", $encsp, mcnt, sf->glyphcnt
watch *(long*)((char*)$encsp+0x48)
next
printf "AFTER MULT CALLOC mult=%p encsp=%p equal=%d mcnt=%d\n", mult, $encsp, mult==$encsp, mcnt
x/12gx $encsp-8
continue
bt 4
continue
quit
