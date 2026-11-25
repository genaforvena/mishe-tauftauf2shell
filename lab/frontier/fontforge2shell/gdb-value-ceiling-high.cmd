set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-value-ceiling-high.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d d=%d\n", min2,max2,min1,max1,tot,max2-min2+1
p/x (i/(max2-min2+1)+min2)*256+(i%(max2-min2+1)+min1)
watch *(long*)((char*)encs-8)
continue
x/gx (char*)encs-8
x/4xb (char*)encs-4
bt 3
quit
