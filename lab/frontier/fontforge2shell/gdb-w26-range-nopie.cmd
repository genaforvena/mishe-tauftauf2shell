set pagination off
break fvimportbdf.c:1750
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/range-full.ff
printf "RANGE full glyph=%d accepted=%d\n", glyph, glyph != 0xffff && glyph < b->glyphcnt
continue
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/range-partial.ff
printf "RANGE partial glyph=%d accepted=%d\n", glyph, glyph != 0xffff && glyph < b->glyphcnt
continue
quit
