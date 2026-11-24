set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-size-consumer.ff
set $encsp = (char*)encs
printf "POISON encsp=%p glyph=%d original_size=%lx\n", $encsp, glyph, *(long*)($encsp-8)
watch *(long*)($encsp-8)
continue
printf "CORRUPTED size=%lx\n", *(long*)($encsp-8)
delete 2
break __libc_malloc if $rdi==128
continue
finish
printf "GETTEXT ret=%p encsp=%p equal=%d size=%lx\n", $rax, $encsp, $rax==$encsp, *(long*)($encsp-8)
watch *(long*)($encsp+0x20)
continue
printf "OVERFLOW at %p value=%lx\n", $encsp+0x20, *(long*)($encsp+0x20)
bt 5
x/24bx $encsp
continue
quit
