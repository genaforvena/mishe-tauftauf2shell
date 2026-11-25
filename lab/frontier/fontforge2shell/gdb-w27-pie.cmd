set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/import-pcf.ff
printf "W27 lane=%s encs=%p encname=%p delta=%ld\n", "pie", encs, encname, (char*)encname-(char*)encs
printf "W27 tounicode=%p fromunicode=%p tounicode_func=%p fromunicode_func=%p\n", encname->tounicode, encname->fromunicode, encname->tounicode_func, encname->fromunicode_func
printf "W27 offsets %ld %ld %ld %ld\n", (char*)&encname->tounicode-(char*)encname, (char*)&encname->fromunicode-(char*)encname, (char*)&encname->tounicode_func-(char*)encname, (char*)&encname->fromunicode_func-(char*)encname
quit
