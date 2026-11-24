set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-sponge.ff
set $encsp = (char*)encs
printf "POISON encs=%p glyph=%d\n", $encsp, glyph
watch *(long*)($encsp-8)
continue
printf "sizeword=%lx\n", *(long*)($encsp-8)
delete 2
break __libc_malloc if $rdi==128
continue
printf "MALLOC128 hit encsp=%p counts7=%d entry7=%p\n", $encsp, tcache->counts[7], tcache->entries[7]
finish
printf "MALLOC128 ret=%p encsp=%p equal=%d\n", $rax, $encsp, $rax==$encsp
bt 6
quit
