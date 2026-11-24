set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-sponge.ff
set $encsp = (char*)encs
printf "encsp=%p\n", $encsp
watch *(long*)($encsp-8)
continue
printf "write1 size=%lx\n", *(long*)($encsp-8)
continue
printf "write2 size=%lx\n", *(long*)($encsp-8)
bt 10
quit
