set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/w26-later-nopie.ff
printf "W26 store encs=%p glyph=%d i=%d\n", encs, glyph, i
set $w26e = encs
break fvimportbdf.c:1469 if props == $w26e
continue
printf "W26 consumer props=%p encs=%p cnt=%d\n", props, $w26e, cnt
dump binary memory /tmp/ff2s-w26-later-nopie.bin (char*)$w26e-131072 (char*)$w26e
info proc mappings
break sfd.c:1671
continue
printf "W26 later pc=%p\n", $pc
quit
