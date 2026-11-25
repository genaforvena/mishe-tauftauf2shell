set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script w24-import.ff
printf "W24 encs=%p glyph=%d i=%d\n", encs, glyph, i
dump binary memory /tmp/ff2s-w24-rel.bin (char*)encs-131072 (char*)encs
info proc mappings
quit
