set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-filechoice.ff
set $encsp=(char*)encs
printf "POISON ptr=%p glyph=%d oldsize=%lx\n", $encsp, glyph, *(long*)($encsp-8)
watch *(long*)($encsp-8)
continue
printf "CORRUPTED size=%lx\n", *(long*)($encsp-8)
delete 2
break __libc_malloc if $rdi==88
continue
finish
printf "CONSUMER ret=%p encsp=%p equal=%d size=%lx\n", $rax, $encsp, $rax==$encsp, *(long*)($encsp-8)
break fvimportbdf.c:1683
continue
bt 5
x/88bx $encsp
x/24bx $encsp+0x28
continue
quit
