set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script w18-import.ff
printf "W18 encs=%p glyph=%d i=%d\n", encs, glyph, i
dump binary memory /tmp/ff2s-w18-pie.bin (char*)encs-131072 (char*)encs
info proc mappings
quit
