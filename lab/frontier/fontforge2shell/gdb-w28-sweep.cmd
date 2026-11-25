set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script /tmp/ff2s-w28-sweep.ff
printf "W28SWEEP bp=%d glyph=%d encs=%p encname=%p delta=%ld tounicode=%p tounicode_func=%p\n", $bpnum, glyph, encs, encname, (char*)encname-(char*)encs, encname->tounicode, encname->tounicode_func
continue
printf "W28SWEEP bp=%d glyph=%d encs=%p encname=%p delta=%ld tounicode=%p tounicode_func=%p\n", $bpnum, glyph, encs, encname, (char*)encname-(char*)encs, encname->tounicode, encname->tounicode_func
continue
printf "W28SWEEP end bp=%d\n", $bpnum
quit
