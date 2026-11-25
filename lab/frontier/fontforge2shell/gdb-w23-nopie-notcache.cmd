set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script w23-import.ff
printf "W23-notcache encs=%p glyph=%d i=%d\n", encs, glyph, i
dump binary memory /tmp/ff2s-w23-nopie-notcache.bin (char*)encs-131072 (char*)encs
info proc mappings
quit
