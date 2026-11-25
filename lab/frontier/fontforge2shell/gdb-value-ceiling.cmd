set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-value-ceiling.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d\n", min2, max2, min1, max1, tot
x/16gx (char*)encs-64
watch *(long*)((char*)encs-8)
continue
printf "size word now:\n"
x/gx (char*)encs-8
printf "four bytes at encs-4:\n"
x/4xb (char*)encs-4
bt 3
continue
quit
