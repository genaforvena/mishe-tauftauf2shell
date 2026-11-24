set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-filechoice.ff
set $encsp=(char*)encs
printf "POISON ptr=%p glyph=%d size=%lx\n", $encsp, glyph, *(long*)($encsp-8)
watch *(long*)$encsp
continue
printf "STOP1 at %p val=%lx\n", $encsp, *(long*)$encsp
bt 4
continue
printf "STOP2 at %p val=%lx\n", $encsp, *(long*)$encsp
bt 4
continue
printf "STOP3 at %p val=%lx\n", $encsp, *(long*)$encsp
bt 4
continue
quit
