# W9: observe a natural-finalization call through the type pointer that the
# image's OOB row wrote. gdb only observes; ASLR is deliberately left ON.
set pagination off
set disable-randomization off
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
set $slot=*(unsigned long*)(0xa2d260+48)
printf "BUF=%p OBJ=%p SLOT=%lx TYPE=%lx\n", $b, $b+176, $slot, *(unsigned long*)($b+184)
break *$slot if $rdi == (void*)($b+176)
continue
# A conditional-breakpoint miss leaves $pc at whatever stopped the inferior
# (typically SIGSEGV), so print the marker only when the stop really matched.
if $pc == $slot && $rdi == (void*)($b+176)
  printf "HIT pc=%p rdi=%p OBJ=%p\n", $pc, $rdi, $b+176
  bt 8
end
continue
