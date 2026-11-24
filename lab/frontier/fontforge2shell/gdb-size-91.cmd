set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-size-91.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
x/2gx encs-16
watch *(long*)((char*)encs-8)
continue
x/2gx encs-16
bt 3
continue
quit
