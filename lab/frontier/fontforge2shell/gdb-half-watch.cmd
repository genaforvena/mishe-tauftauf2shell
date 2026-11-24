set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-half.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
print/x (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1)
watch *(int*)((char*)encs-16)
continue
printf "WATCH HIT at %p\n", (char*)encs-16
print/x *(int*)((char*)encs-16)
x/4xb (char*)encs-16
x/24xb (char*)encs-16
bt 3
quit
