set pagination off
set confirm off
set breakpoint pending on
break ImagingJpegDecode
run
set $st = state
printf "ENTRY buffer=%p bytes=%d xsize=%d ysize=%d\n", $st->buffer, $st->bytes, $st->xsize, $st->ysize
set $deep = (unsigned char *)($st->buffer + 200)
watch *$deep
continue
printf "DEEP WATCH HIT\n"
x/16bx $st->buffer
x/16bx $st->buffer+200
quit
