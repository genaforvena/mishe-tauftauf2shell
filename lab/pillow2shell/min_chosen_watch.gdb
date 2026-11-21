# W9: prove the chosen ob_type byte came from the pinned scanline caller.
set pagination off
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
printf "BUF=%p BEFORE_TYPE=%lx\n", $b, *(unsigned long*)($b+184)
watch *(unsigned char*)($b+184)
continue
printf "WATCH pc=%p type=%lx\n", $pc, *(unsigned long*)($b+184)
bt 6
continue
printf "AFTER_TYPE=%lx\n", *(unsigned long*)($b+184)
quit
