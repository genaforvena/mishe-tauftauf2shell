set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-sponge.ff
set $encsp = (char*)encs
watch *(long*)($encsp-8)
continue
delete 2
break __libc_malloc if $rdi>=0x71 && $rdi<=0x88
continue
printf "MALLOC req=%lx ret=%p encsp=%p eq=%d\n", $rdi, $rax, $encsp, $rax==$encsp
bt 6
continue
printf "MALLOC2 req=%lx ret=%p eq=%d\n", $rdi, $rax, $rax==$encsp
bt 6
continue
quit
