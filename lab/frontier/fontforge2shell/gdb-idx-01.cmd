set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-idx-01.ff
printf "HIT glyph=%d i=%d encs=%p\n", glyph, i, encs
quit
