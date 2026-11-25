set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-value-atk50.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
x/16gx (char*)encs-224
watch *(long*)((char*)encs-200)
continue
printf "after write, pointer word at encs-200:\n"
x/gx (char*)encs-200
x/4xb (char*)encs-200
continue
printf "end of run\n"
bt 4
quit
