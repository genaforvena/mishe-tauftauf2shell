set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-negdiv-atk.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d\n", min2, max2, min1, max1, tot
x/2gx (char*)encs-208
watch *(long*)((char*)encs-200)
continue
printf "after write, pointer word at encs-200:\n"
x/gx (char*)encs-200
x/4xb (char*)encs-200
info proc mappings
continue
printf "end of run\n"
bt 3
quit
