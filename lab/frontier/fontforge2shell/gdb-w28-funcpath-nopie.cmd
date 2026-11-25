set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
break encoding.c:2593
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/import-funcpath.ff
printf "W28S1 bp=%d glyph=%d encs=%p encname=%p delta=%ld tounicode=%p tounicode_func=%p\n", $bpnum, glyph, encs, encname, (char*)encname-(char*)encs, encname->tounicode, encname->tounicode_func
continue
printf "W28S2 bp=%d glyph=%d encs=%p encname=%p delta=%ld tounicode=%p tounicode_func=%p\n", $bpnum, glyph, encs, encname, (char*)encname-(char*)encs, encname->tounicode, encname->tounicode_func
continue
printf "W28S3 bp=%d\n", $bpnum
bt 6
quit
