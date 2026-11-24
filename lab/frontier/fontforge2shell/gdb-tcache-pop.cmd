set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-filechoice.ff
set $encsp=(char*)encs
printf "POISON ptr=%p glyph=%d size=%lx\n", $encsp, glyph, *(long*)($encsp-8)
watch tcache->entries[5]
continue
printf "STOP1 entries5=%p encsp=%p\n", tcache->entries[5], $encsp
bt 4
continue
printf "STOP2 entries5=%p encsp=%p\n", tcache->entries[5], $encsp
bt 6
continue
printf "STOP3 entries5=%p encsp=%p\n", tcache->entries[5], $encsp
bt 6
continue
quit
