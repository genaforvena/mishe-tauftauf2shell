set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/w25-late.ff
printf "W25 encs=%p glyph=%d i=%d\n", encs, glyph, i
set $w25e = encs
break sfd.c:1671
continue
printf "W25 late pc=%p\n", $pc
dump binary memory /tmp/ff2s-w25-late-nopie.bin (char*)$w25e-131072 (char*)$w25e
info proc mappings
quit
