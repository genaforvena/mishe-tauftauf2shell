set pagination off
set confirm off
set breakpoint pending on
set print elements 80
break ImagingJpegDecode
run
info args
set $st = state
printf "ENTRY buffer=%p bytes=%d xsize=%d ysize=%d\n", $st->buffer, $st->bytes, $st->xsize, $st->ysize
printf "CINFO via state context: width=%d comps=%d\n", ((JPEGSTATE*)$st->context)->cinfo.output_width, ((JPEGSTATE*)$st->context)->cinfo.output_components
set $oob = (unsigned char *)($st->buffer + $st->bytes)
watch *$oob
continue
printf "WATCH HIT at %s\n", $pc
x/80bx $st->buffer
quit
