set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
dump binary memory /tmp/pw2-w4/heap_orig.bin $b+128 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
printf "AFTER_DECODE type=%lx\n",*(unsigned long*)($b+184)
restore /tmp/pw2-w4/heap_orig.bin binary $b+128
set *(unsigned long*)($b+184)=0xa2d260
printf "AFTER_RESTORE type=%lx sizefield=%lx\n",*(unsigned long*)($b+184),*(unsigned long*)($b+136)
continue
printf "CRASH pc=%p TYPE=%lx\n",$pc,*(unsigned long*)($b+184)
x/16i $pc-32
info registers rax rbx rcx rdx rdi rsi r8
bt 8
