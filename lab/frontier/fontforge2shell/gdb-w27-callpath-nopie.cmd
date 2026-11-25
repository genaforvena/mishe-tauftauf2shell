set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/import-callpath.ff
printf "W27C lane=nopie before glyph=%d tounicode=%p\n", glyph, encname->tounicode
next
next
next
printf "W27C lane=nopie after glyph=%d tounicode=%p\n", glyph, encname->tounicode
break iconv
continue
printf "W27C lane=nopie iconv cd=%p\n", $rdi
bt 3
continue
printf "W27C lane=nopie pc=%p\n", $pc
quit
