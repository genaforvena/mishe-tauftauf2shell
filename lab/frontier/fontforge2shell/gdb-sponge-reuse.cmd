set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-sponge.ff
set $encsp = encs
printf "POISON encs=%p glyph=%d\n", $encsp, glyph
watch *(long*)((char*)$encsp-8)
continue
printf "sizeword now=%lx\n", *(long*)($encsp-8)
delete 2
break fvimportbdf.c:1676
continue
printf "SECOND IMPORT offsets=%p encsp=%p equal=%d cnt=%d\n", offsets, $encsp, offsets==$encsp, cnt
printf "chunk size word at offsets-8=%lx\n", *(long*)(offsets-8)
x/8gx offsets
continue
printf "done\n"
quit
