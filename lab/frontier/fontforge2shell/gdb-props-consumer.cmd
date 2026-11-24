set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-filechoice.ff
set $encsp=(char*)encs
printf "POISON ptr=%p glyph=%d size=%lx\n", $encsp, glyph, *(long*)($encsp-8)
delete 1
break fvimportbdf.c:1469 if props==$encsp
continue
printf "PROPS ptr=%p encsp=%p equal=%d cnt=%d\n", props, $encsp, props==$encsp, cnt
bt 3
x/96bx props
continue
quit
