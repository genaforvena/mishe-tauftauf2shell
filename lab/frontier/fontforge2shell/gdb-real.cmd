set pagination off
set confirm off
set environment ASAN_OPTIONS detect_leaks=0:abort_on_error=0:halt_on_error=0
break fvimportbdf.c:1751 if glyph < 0
run -script import-pcf.ff
printf "HIT glyph=%d i=%d encs=%p b->glyphcnt=%d\n", glyph, i, encs, b->glyphcnt
printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d\n", min2, max2, min1, max1, tot
print/x (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1)
next
next
printf "AFTER second step: encs=%p\n", encs
print/x encs[-1]
x/4xb encs-4
bt 3
quit
