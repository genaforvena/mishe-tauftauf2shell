set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
printf "BUF=%p BEFORE_TYPE=%lx\n",$b,*(unsigned long*)($b+184)
watch *(unsigned char*)($b+184)
continue
printf "STORE pc=%p TYPE_NOW=%lx\n",$pc,*(unsigned long*)($b+184)
x/4gx $b+176
bt 5
continue
printf "CRASH pc=%p\n",$pc
bt 12
info symbol 0x61d988
info symbol 0x55984c
info symbol 0x61cbe6
info symbol 0x61c5d1
info symbol 0x5fc343
