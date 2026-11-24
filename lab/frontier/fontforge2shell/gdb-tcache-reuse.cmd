set pagination off
break fvimportbdf.c:1770
run -script import-size-91.ff
set $e = encs
printf "ENC=%p\n", $e
x/gx (char*)$e-8
break fvimportbdf.c:1771
continue
printf "AFTER FREE tcache[7]=%p\n", tcache->entries[7]
break __libc_malloc if $rdi>=0x71 && $rdi<=0x88
commands
silent
printf "MALLOC req=%#lx\n", $rdi
finish
printf "MALLOC ret=%p enc=%p\n", $rax, $e
continue
end
continue
printf "STOPPED\n"
quit
